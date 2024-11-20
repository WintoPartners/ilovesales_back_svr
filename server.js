import express from "express";
import multer from "multer";
import path from "path";
import fs from "fs";
import axios from "axios";
import FormData from "form-data";
import cors from "cors";
import OpenAI from "openai";
import * as dotenv from "dotenv";
import pkg from 'pg';
import session from 'express-session';
import { v4 as uuidv4 } from 'uuid';
import pgSession from 'connect-pg-simple';
import solapi from 'solapi';
import nodemailer from 'nodemailer';
import Replicate from "replicate";
import bcrypt from "bcrypt";
import bodyParser from 'body-parser';
import pdf from 'pdf-parse';

const { Pool } = pkg;
const pgStore = pgSession(session);
dotenv.config();

const app = express();
app.set('trust proxy', 1);
// PostgreSQL 연결 설정
const pool = new Pool({
  user: 'postgres',
  host: process.env.DBURL,
  database: 'dev',
  password: process.env.DBPASSWORD,
  port: 5432,
  ssl: {
      rejectUnauthorized: false // SSL 인증서 검증 비활성화
  },
});
if(process.env.ENV === 'production'){
  app.use(session({
    store: new pgStore({
      pool: pool,
      tableName: 'session'
    }),
    secret: "secret key",
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 3600000, // 1 hour
      secure: true,
      httpOnly: true,
      sameSite: 'None'
    }
  }));
}else{
  app.use(session({
    store: new pgStore({
      pool: pool, // 위에서 생성한 PostgreSQL pool 인스턴스
      tableName: 'session' // 사용할 테이블 이름 (없다면 자동으로 생성됩니다)
  }),
    secret: "secret key",
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 3600000 },
  }));
}




const corsOptions = {
  origin: process.env.URL,
  credentials: true, // withCredentials: true와 함께 사용하려면 true로 설정
};


app.use(cors(corsOptions));
// app.use((req, res, next) => {
//   res.header('Access-Control-Allow-Credentials', 'true');
//   next();
// });  

app.use(express.json()); // JSON 형식의 본문을 파싱
app.use(express.urlencoded({ extended: true })); // URL 인코딩된 본문을 파싱
app.use(bodyParser.json());

const saltRounds = 10;

const transporter = nodemailer.createTransport({
  service: 'gmail', // 이메일 서비스 제공자
  auth: {
    user: process.env.EMAIL_USERNAME, // 환경변수에서 이메일 계정 정보 가져오기
    pass: process.env.EMAIL_PASSWORD  // 환경변수에서 이메일 패스워드 정보 가져오기
  }
});

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

async function getProjectInfoByUserIp(userId) {
    const query = `
        SELECT pro_name, pro_period, pro_budget, pro_agency,pro_function, pro_skill,pro_description,pro_reference
        FROM rfp_temp
        WHERE user_session = $1
        LIMIT 1;
    `;
    try {
        const res = await pool.query(query, [userId]);
        return res.rows[0]; // 조회된 첫 번째 행을 반환
    } catch (err) {
        console.error(err);
        throw err;
    }
}


const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, process.env.FILEPATH); // 파일이 저장될 경로
    },
    filename: (req, file, cb) => {
        cb(null, file.originalname); // 파일 원본 이름으로 저장
    },
});

const upload = multer({ storage: storage });

function cleanText(text) {
  // 공백 문자를 제외한 모든 특수 문자를 제거합니다.
  return text.replace(/[^\w\sㄱ-ㅎ가-힣]/g, '');
}

async function extractTextFromPDF(filePath) {
  try {
    const dataBuffer = fs.readFileSync(filePath);
    const data = await pdf(dataBuffer);
    const cleanedText = cleanText(data.text); // 클린징 적용
    return cleanedText;
  } catch (err) {
    console.error('Error extracting text from PDF:', err);
    throw err;
  }
}

// Threads
// Create Thread
// 파일 업로드 라우트

app.post('/skip',  async (req, res) => {
  try{
    const id = req.session.userInfo.userId
    const subscriptionQuery = 'SELECT subscription_status FROM user_info WHERE user_id = $1';
    const subscriptionResult = await pool.query(subscriptionQuery, [id]);
    const subscriptionStatus = subscriptionResult.rows.length > 0 ? subscriptionResult.rows[0].subscription_status : null;
    if (subscriptionResult.rows.length > 0 && subscriptionResult.rows[0].subscription_status === 'N') {
        return res.status(200).send({
          message: 'Not Subscript',
          additionalInfo: {
              subscriptionStatus: subscriptionStatus
          }
      });
    }
    req.session.userId = uuidv4();
    req.session.save(err => {
      if (err) {
          // 세션 저장 실패 처리
          console.error(err);
          return res.status(500).send('Internal Server Error'); // 클라이언트에 에러 메시지 전송
      }
      res.status(200).send({
      message: 'Session `update`d successfully',
      additionalInfo: {
          subscriptionStatus: subscriptionStatus
        }// 성공적으로 처리되었음을 알림
      });
    })
  }catch(err){
    console.error(err);
    res.status(500).send('Error saving file information to database.');
  }
  
});
app.post('/upload', upload.single('file'), async (req, res) => {
  const file = req.file;
  req.session.userId = uuidv4();
  req.session.save(err => {
    if (err) {
      console.error(err);
    }
  });

  if (!file) {
    return res.status(400).send('No file uploaded.');
  }

  try {
    const id = req.session.userInfo.userId;
    const subscriptionQuery = 'SELECT subscription_status FROM user_info WHERE user_id = $1';
    const subscriptionResult = await pool.query(subscriptionQuery, [id]);
    const subscriptionStatus = subscriptionResult.rows.length > 0 ? subscriptionResult.rows[0].subscription_status : null;

    if (subscriptionResult.rows.length > 0 && subscriptionResult.rows[0].subscription_status === 'N') {
      return res.send({
        message: 'Not Subscript',
        additionalInfo: {
          subscriptionStatus: subscriptionStatus
        }
      });
    }

    const { originalname, size } = file;
    const query = 'INSERT INTO voice_file (file_name, file_size) VALUES ($1, $2)';
    const values = [originalname, size];
    await pool.query(query, values);

  } catch (err) {
    console.error(err);
    return res.status(500).send('Error saving file information to database.');
  }

  const filePath = path.resolve(process.env.FILEPATH + file.originalname); // Multer에 의해 저장된 파일 경로
  let recognizedText = '';

  if (file.mimetype === 'application/pdf') {
    try {
      recognizedText = await extractTextFromPDF(filePath);
    } catch (error) {
      console.error('Error extracting text from PDF:', error.message);
      return res.status(500).send('Error extracting text from PDF.');
    }
  } else if (file.mimetype === 'text/plain') {
    try {
      recognizedText = fs.readFileSync(filePath, 'utf8'); // 텍스트 파일의 내용을 읽어옴
    } catch (error) {
      console.error('Error reading text file:', error.message);
      return res.status(500).send('Error reading text file.');
    }
  } else {
    const clientSecret = process.env.CLIENTSECRET;
    const formData = new FormData();
    formData.append('media', fs.createReadStream(filePath));
    formData.append('params', JSON.stringify({
      language: 'ko-KR',
      completion: 'sync',
      resultToObs: 'false'
    }));

    try {
      const response = await axios.post(process.env.CLOVAURL, formData, {
        headers: {
          ...formData.getHeaders(),
          'X-CLOVASPEECH-API-KEY': clientSecret
        }
      });
      recognizedText = response.data.text;
    } catch (error) {
      console.error('Error in API call:', error.message);
      return res.status(500).send('API call failed');
    }
  }

  try {
    const result = await pool.query(
      'INSERT INTO text_file_test (text_contents) VALUES ($1) RETURNING *',
      [recognizedText]
    );
    const assistant = await openai.beta.assistants.retrieve(
      process.env.GPTSKEY1
    );
    const thread = await openai.beta.threads.create();

    await openai.beta.threads.messages.create(thread.id, {
      role: "user",
      content: recognizedText
    });
    const run = await openai.beta.threads.runs.create(thread.id, {
      assistant_id: assistant.id,
      instructions: "",
    });
    await checkRunStatus(openai, thread.id, run.id);

    await pool.query(
      'INSERT INTO thread_id (thread_id, user_session) VALUES ($1, $2) ON CONFLICT (user_session) DO UPDATE SET thread_id = EXCLUDED.thread_id RETURNING *',
      [run.thread_id, req.session.userId]
    );

    const queryResult = await pool.query(
      'SELECT thread_id FROM thread_id WHERE user_session = $1;',
      [req.session.userId]
    );

    const message = await openai.beta.threads.messages.list(thread.id);
    const contents = message.body.data[0].content[0].text.value;
    const sections = contents.split(/\n(?=[A-Z가-힣\s]+:)/);

    const extractedInfo = {
      projectName: '',
      budget: '',
      duration: '',
      agency: '',
      function: '',
      skill: '',
      description: ''
    };

    sections.forEach(section => {
      if (section.startsWith('프로젝트 이름')) {
        extractedInfo.projectName = section.split(': ')[1];
      } else if (section.startsWith('예산')) {
        extractedInfo.budget = section.split(': ')[1].replace(',', '');
      } else if (section.startsWith('기간')) {
        extractedInfo.duration = section.split(': ')[1].replace(',', '');
      } else if (section.startsWith('에이전시 종류')) {
        extractedInfo.agency = section.split(': ')[1];
      } else if (section.startsWith('구체적 기능')) {
        extractedInfo.function = section.split(': ')[1];
      } else if (section.startsWith('기술 스택')) {
        extractedInfo.skill = section.split(': ')[1].replace(',', '');
      } else if (section.startsWith('설명')) {
        extractedInfo.description = section.split(': ')[1];
      }
    });

    const values = [
      extractedInfo.projectName,
      extractedInfo.duration,
      extractedInfo.budget,
      extractedInfo.agency,
      extractedInfo.function,
      extractedInfo.skill,
      extractedInfo.description,
      req.session.userId
    ];
    const checkQuery = `SELECT * FROM rfp_temp WHERE user_session = $1;`;
    const checkResult = await pool.query(checkQuery, [req.session.userId]);

    if (checkResult.rows.length > 0) {
      const updateQuery = `
        UPDATE rfp_temp
        SET pro_name = $1, pro_period = $2, pro_budget = $3, pro_agency = $4, pro_function = $5, pro_skill = $6, pro_description = $7
        WHERE user_session = $8
        RETURNING *;
      `;
      await pool.query(updateQuery, values);
    } else {
      const insertQuery = `
        INSERT INTO rfp_temp (pro_name, pro_period, pro_budget, pro_agency, pro_function, pro_skill, pro_description, user_session)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING *;
      `;
      await pool.query(insertQuery, values);
    }

    const sendResult = await pool.query('SELECT * FROM rfp_temp WHERE user_session = $1', [req.session.userId]);

    return res.send({
      message: 'File uploaded and data inserted into database successfully.',
      additionalInfo: {
        projectName: sendResult.rows[0].pro_name,
        budget: sendResult.rows[0].pro_budget,
        duration: sendResult.rows[0].pro_period,
      }
    });
  } catch (error) {
    console.error('Error while fetching messages:', error.message);
    return res.status(500).send('Database error.');
  }
});


app.post('/projectInfo', async (req, res) => {
    try {
        const userId = req.session.userId; // 미들웨어에서 설정한 사용자 IP 주소 사용
        const projectInfo = await getProjectInfoByUserIp(userId);
        res.json(projectInfo);
    } catch (error) {
        res.status(500).send('Server error while fetching project info.');
    }
});


app.post('/proAbout', async (req, res) => {
    const { projectName, budget, duration } = req.body;
    const userId = req.session.userId; // 사용자 IP는 미들웨어에서 설정된 것을 사용
    try {
      // 먼저 해당 사용자의 데이터가 있는지 확인
      const checkQuery = 'SELECT * FROM rfp_temp WHERE user_session = $1';
      const checkRes = await pool.query(checkQuery, [userId]);
  
      if (checkRes.rows.length > 0) {
        // 데이터가 있으면 UPDATE
        const updateQuery = `
          UPDATE rfp_temp
          SET pro_name = $1, pro_budget = $2, pro_period = $3
          WHERE user_session = $4
        `;
        await pool.query(updateQuery, [projectName, budget, duration, userId]);
      } else {
        // 데이터가 없으면 INSERT (예시 로직, 실제 컬럼 및 데이터에 맞게 조정 필요)
        const insertQuery = `
          INSERT INTO rfp_temp (pro_name, pro_budget, pro_period, user_session)
          VALUES ($1, $2, $3, $4)
        `;
        await pool.query(insertQuery, [projectName, budget, duration, userId]);
      }
      res.send('Data updated successfully');
    } catch (error) {
      console.error('Database error:', error);
      res.status(500).send('Server error');
    }
  });

  app.post('/updateAgencyNumbers', async (req, res) => {
    const agencyNumbers = req.body;
    const userId = req.session.userId;
    try {
      const checkQuery = 'SELECT * FROM rfp_temp WHERE user_session = $1';
      const checkResult = await pool.query(checkQuery, [userId]);
  
      if (checkResult.rows.length > 0) {
        // 데이터가 있으면 UPDATE
        const updateQuery = 'UPDATE rfp_temp SET pro_agency = $1 WHERE user_session = $2';
        await pool.query(updateQuery, [agencyNumbers.join(','), userId]); // agencyNumbers 배열을 문자열로 변환하여 저장
      } else {
        // 데이터가 없으면 INSERT
        const insertQuery = 'INSERT INTO rfp_temp (pro_agency, user_session) VALUES ($1, $2)';
        await pool.query(insertQuery, [agencyNumbers.join(','), userId]);
      }
      res.json({ message: 'Agency numbers updated successfully' });
    } catch (error) {
      console.error('Database error:', error);
      res.status(500).send('Server error');
    }
  });

  app.post('/updateSkillNumbers', async (req, res) => {
    const { skillNumber } = req.body;
    const userId = req.session.userId;
    try {
      const checkQuery = 'SELECT * FROM rfp_temp WHERE user_session = $1';
      const checkResult = await pool.query(checkQuery, [userId]);
  
      if (checkResult.rows.length > 0) {
        // 데이터가 있으면 UPDATE
        const updateQuery = 'UPDATE rfp_temp SET pro_skill = $1 WHERE user_session = $2';
        await pool.query(updateQuery, [skillNumber, userId]); // agencyNumbers 배열을 문자열로 변환하여 저장
      } else {
        // 데이터가 없으면 INSERT
        const insertQuery = 'INSERT INTO rfp_temp (pro_skill, user_session) VALUES ($1, $2)';
        await pool.query(insertQuery, [skillNumber, userId]);
      }
      res.json({ message: 'skillNumber numbers updated successfully' });
    } catch (error) {
      console.error('Database error:', error);
      res.status(500).send('Server error');
    }
  });

  app.post('/updateDescription', async (req, res) => {
    const { description,urlText } = req.body;
    const userId = req.session.userId;
    try {
      const checkQuery = 'SELECT * FROM rfp_temp WHERE user_session = $1';
      const checkResult = await pool.query(checkQuery, [userId]);
  
      if (checkResult.rows.length > 0) {
        // 데이터가 있으면 UPDATE
        const updateQuery = 'UPDATE rfp_temp SET pro_description = $1,pro_reference = $2 WHERE user_session = $3';
        await pool.query(updateQuery, [description, urlText, userId]); // agencyNumbers 배열을 문자열로 변환하여 저장
      } else {
        // 데이터가 없으면 INSERT
        const insertQuery = 'INSERT INTO rfp_temp (pro_description, pro_reference, user_session) VALUES ($1, $2, $3)';
        await pool.query(insertQuery, [description, urlText, userId]);
      }
      res.json({ message: 'Description updated successfully' });
    } catch (error) {
      console.error('Database error:', error);
      res.status(500).send('Server error');
    }
  });

  app.post('/updatefunctionNumbers', async (req, res) => {
    const { functionNumbers } = req.body;
    const filteredFunctionNumbers = functionNumbers.filter(number => number !== 'null');
    const userId = req.session.userId;
    try {
      const checkQuery = 'SELECT * FROM rfp_temp WHERE user_session = $1';
      const checkResult = await pool.query(checkQuery, [userId]);
      if (checkResult.rows.length > 0) {
        // 데이터가 있으면 UPDATE
        const updateQuery = 'UPDATE rfp_temp SET pro_function = $1 WHERE user_session = $2';
        await pool.query(updateQuery, [filteredFunctionNumbers.join(','), userId]); // agencyNumbers 배열을 문자열로 변환하여 저장
      } else {
        // 데이터가 없으면 INSERT
        const insertQuery = 'INSERT INTO rfp_temp (pro_function, user_session) VALUES ($1, $2)';
        await pool.query(insertQuery, [filteredFunctionNumbers.join(','), userId]);
      }
      const result = await pool.query(checkQuery, [userId]);
      const row = result.rows[0];
      const outputString = `
        프로젝트 이름 : ${row.pro_name},
        프로젝트 기간 : ${row.pro_period},
        프로젝트 예산 : ${row.pro_budget},
        프로젝트 에이전시 유형 : ${row.pro_agency},
        프로젝트 기능 : ${row.pro_function},
        프로젝트 개발방식 : ${row.pro_skill},
        프로젝트 설명 : ${row.pro_description}
        `;
        try {
      
      const gptKeys = [
        process.env.GPTSKEY2,
        process.env.GPTSKEY3,
        process.env.GPTSKEY4,
        process.env.GPTSKEY5
      ];

      const promises = gptKeys.map(key =>
        gptsApi(outputString, key, userId).catch(error => console.error(`Error with key ${key}:`, error))
      );
      const results = await Promise.all(promises);
      const project = results[0];
      const output = results[1].split("필요 산출물:")[1].trim();
      const service = results[2].split("서비스 요구사항:")[1].trim();
      let funcDesc = '';
      if (results[3] && results[3].includes("기능명세서:")) {
        funcDesc = results[3].split("기능명세서:")[1].trim();
      } else {
          // 예외 처리: 기능명세서가 없는 경우, 빈 문자열이나 기본 값을 설정
          funcDesc = '기능명세서가 없습니다.';
      }

      const selectIAQuery = 'SELECT * FROM ia WHERE ia_id = $1';
      const selectIAResult = await pool.query(selectIAQuery, [userId]);
  
      // 레코드가 이미 존재하면, 해당 레코드 삭제
      if (selectIAResult.rows.length > 0) {
        const deleteQuery = 'DELETE FROM ia WHERE ia_id = $1';
        await pool.query(deleteQuery, [userId]);
      }
       // parseLogData 함수는 로그 데이터를 파싱하는 가상의 함수입니다.

      const contentLines = project.split('\n'); // 내용을 줄 단위로 분리
      const projectInfo = {};
      let currentSection = '';
      contentLines.forEach(line => {
        // 각 섹션 제목을 확인하여 currentSection 업데이트
        if (line.includes('프로젝트 이름:') || line.includes('프로젝트 예산:') ||
            line.includes('프로젝트 기간:')) {
            let [key, value] = line.split(':').map(part => part.trim());
            projectInfo[key] = value; // 섹션 제목 다음에 오는 내용만 저장
            currentSection = ''; // 섹션 제목을 처리한 후 currentSection 초기화
        } else if (line.startsWith('작업분해구조(WBS):')) {
          currentSection = '작업분해구조(WBS)'; // 현재 섹션을 '작업분해구조(WBS)'로 업데이트
          projectInfo[currentSection] = ''; // 내용을 담을 빈 문자열 할당
        } else if (currentSection) {
            // 현재 섹션의 내용 추가 (여기서 '\n'은 필요에 따라 추가하거나 생략할 수 있음)
            projectInfo[currentSection] += (projectInfo[currentSection] ? '\n' : '') + line.trim();
        }
    });
      Object.keys(projectInfo).forEach(key => {
        // 값의 끝에 위치한 콤마를 제거합니다. 정규 표현식을 사용해 콤마와 공백을 처리합니다.
        projectInfo[key] = projectInfo[key].replace(/,\s*$/, '');
    });
    const agencyMapping = {
      '1': '영상/사진',
      '2': '브랜딩',
      '3': '앱 개발',
      '4': '웹 개발',
      '5': '디자인',
      '6': '마케팅',
      '7': '번역/통역',
      '8': '컨설팅',
    };
    const wbs_doc = projectInfo['작업분해구조(WBS)'];
    const proAgencyText = row.pro_agency.split(',')
                                .map(number => agencyMapping[number])
                                .join('/');
      const query = `
        INSERT INTO rfp(pro_name, pro_budget, pro_period, pro_service, pro_output, pro_reference, pro_ia, pro_wbs, user_session, expected_budget,expected_period, pro_agency,user_id,pro_funcdesc,wbs_doc)
        VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,$15)
        ON CONFLICT (user_session) DO UPDATE SET
          pro_name = EXCLUDED.pro_name,
          pro_budget = EXCLUDED.pro_budget,
          pro_period = EXCLUDED.pro_period,
          pro_service = EXCLUDED.pro_service,
          pro_output = EXCLUDED.pro_output,
          pro_reference = EXCLUDED.pro_reference,
          pro_ia = EXCLUDED.pro_ia,
          pro_wbs = EXCLUDED.pro_wbs,
          expected_budget = EXCLUDED.expected_budget,
          expected_period = EXCLUDED.expected_period,
          pro_agency = EXCLUDED.pro_agency,
          user_id = EXCLUDED.user_id,
          pro_funcdesc = EXCLUDED.pro_funcdesc,
          wbs_doc = EXCLUDED.wbs_doc
      `;
      const values = [
        projectInfo['프로젝트 이름'],
        projectInfo['프로젝트 예산'], // "4500만원"에서 숫자만 추출
        projectInfo['프로젝트 기간'], // "5개월"에서 숫자만 추출
        service,
        output,
        row.pro_reference, // 배열을 문자열로 변환
        userId,
        // "기능명세서" 및 "작업분해구조(WBS)" 처리 로직 추가 필요
        userId,
        userId, // user_session에 userId를 사용
        row.pro_budget,
        row.pro_period,
        proAgencyText,
        req.session.userInfo.userId,
        funcDesc,
        wbs_doc
      ];
      try {
        const res = await pool.query(query, values);
      } catch (err) {
        console.error('Error executing query', err.stack);
      }
      const parsedData = parseAndInsertData(funcDesc,userId);
      const wbsItems = projectInfo['작업분해구조(WBS)'].split('-').map(item => item.trim()).filter(item => item);
      // values 배열을 위에서 추출한 정보로 채워 넣고 쿼리 실행
      // 각 wbsItems 항목에 대해 반복 실행 필요
    // wbsItems 항목에 대해 실행
      const selectQuery = 'SELECT * FROM wbs WHERE wbs_id = $1';
          const selectResult = await pool.query(selectQuery, [userId]);
      
          // 레코드가 이미 존재하면, 해당 레코드 삭제
          if (selectResult.rows.length > 0) {
            const deleteQuery = 'DELETE FROM wbs WHERE wbs_id = $1';
            await pool.query(deleteQuery, [userId]);
          }
      wbsItems.forEach(async (item, index) => {
        try {
          // 새로운 레코드 삽입
          const [taskDetail, duration] = item.split(':').map(part => part.trim());
          const [taskName, roles] = taskDetail.split('(').map(part => part.trim().replace(')', ''));
          const [startMonth, endMonth] = duration.split('~').map(part => parseFloat(part.replace('개월', '').trim()));
          const wbsId = userId;
          const insertQuery = `
            INSERT INTO wbs (wbs_id, task_name, roles_involved, start_month, end_month, description)
            VALUES ($1, $2, $3, $4, $5, $6)
          `;
          const wbsValues = [wbsId, taskName, roles, startMonth, endMonth, '']; // description이 없으므로 빈 문자열 사용
          await pool.query(insertQuery, wbsValues);
      
        } catch (err) {
          console.error('Error processing WBS item', err.stack);
        }
      });
      
      } catch (error) {
        console.error('AI호출 오류', error);
      }
      res.json({ message: 'functionNumbers updated successfully' });
    } catch (error) {
      console.error('Database error:', error);
      res.status(500).send('Server error');
    }
  });

  app.post('/setWbs', async (req, res) => {
    try {
        const userId = req.session.userId;; 
        const { rows } = await pool.query('SELECT wbs_id, task_name, roles_involved, start_month, end_month FROM wbs WHERE wbs_id = $1 order by start_month asc,end_month asc;',[userId]);
        res.json(rows);
    } catch (error) {
        res.status(500).send('Server error while fetching project info.');
    }
});

app.post('/setFuncDesc', async (req, res) => {
  try {
      const userId = req.session.userId;; 
      const { rows } = await pool.query('SELECT pro_funcdesc,wbs_doc FROM rfp WHERE user_session = $1;',[userId]);
      res.json(rows);
  } catch (error) {
      res.status(500).send('Server error while fetching project info.');
  }
});

app.post('/setProject', async (req, res) => {
  try {
      const userId = req.session.userId;; 
      const { rows } = await pool.query('SELECT pro_name, pro_budget, pro_period, pro_service, pro_output, expected_budget,expected_period, pro_agency, pro_reference FROM rfp WHERE user_session = $1;',[userId]);
      const parsedRows = rows.map(row => {
        // pro_service 필드의 내용을 줄별로 분리합니다.
        const services = row.pro_service.split(',\n');
        
        // 각 줄에서 끝에 있는 콤마를 제거하고, 다시 줄바꿈 문자로 합칩니다.
        const parsedProService = services.map(service => service.trim()).join('\n');
        
        // 수정된 pro_service로 객체를 업데이트합니다.
        return { ...row, pro_service: parsedProService };
      });
      res.json(parsedRows);
  } catch (error) {
      res.status(500).send('Server error while fetching project info.');
  }
});

app.post('/setIA', async (req, res) => {
  try {
      const userId = req.session.userId;; 
      const { rows } = await pool.query('SELECT depth1,depth2,depth3,depth4 FROM ia WHERE ia_id = $1 order by ia_num asc,ia_seq asc;',[userId]);

      const depth1Counts = rows.reduce((acc, cur) => {
        acc[cur.depth1] = (acc[cur.depth1] || 0) + 1;
        return acc;
      }, {});
      
      // depth2의 유니크한 조합을 체크하기 위한 객체
      const depth2Unique = {};
      const depth3Unique = {};

      rows.forEach(row => {
        if (row.depth2 !== '-') {
          const key = `${row.depth1}-${row.depth2}`;
          depth2Unique[key] = (depth2Unique[key] || 0) + 1;
        }
        if (row.depth3 !== '-') {
          const key = `${row.depth1}-${row.depth2}-${row.depth3}`;
          depth3Unique[key] = (depth3Unique[key] || 0) + 1;
        }
      });

      const filteredRows = rows.filter(row => {
        // depth1만 존재하고 그것이 유일한 경우 유지
        if (row.depth2 === '-' && depth1Counts[row.depth1] === 1) return true;

        // depth2가 있고, 해당 depth2가 유니크한 경우(다른 행에 동일한 depth2가 존재하지 않는 경우) 유지
        if (row.depth2 !== '-' && row.depth3 === '-' && depth2Unique[`${row.depth1}-${row.depth2}`] === 1) return true;

        // depth3가 있고, 해당 depth3가 유니크한 경우(다른 행에 동일한 depth3가 존재하지 않는 경우) 유지
        if (row.depth3 !== '-' && row.depth4 === '-' && depth3Unique[`${row.depth1}-${row.depth2}-${row.depth3}`] === 1) return true;

        // depth4가 있는 경우 모두 유지
        if (row.depth4 !== '-') return true;

        // 위 조건에 해당하지 않는 행은 필터링
        return false;
      });

      res.json(filteredRows);
  } catch (error) {
      res.status(500).send('Server error while fetching project info.');
  }
});

app.post('/retry', async (req, res) => {
  const userId = req.session.userId;
  try {
    const checkQuery = 'SELECT * FROM rfp_temp WHERE user_session = $1';
    const result = await pool.query(checkQuery, [userId]);
    const row = result.rows[0];
    const outputString = `
      프로젝트 이름 : ${row.pro_name},
      프로젝트 기간 : ${row.pro_period},
      프로젝트 예산 : ${row.pro_budget},
      프로젝트 에이전시 유형 : ${row.pro_agency},
      프로젝트 기능 : ${row.pro_function},
      프로젝트 개발방식 : ${row.pro_skill},
      프로젝트 설명 : ${row.pro_description}
      `;
      try {
    
    const gptKeys = [
      process.env.GPTSKEY2,
      process.env.GPTSKEY3,
      process.env.GPTSKEY4,
      process.env.GPTSKEY5
    ];

    const promises = gptKeys.map(key =>
      gptsApi(outputString, key, userId).catch(error => console.error(`Error with key ${key}:`, error))
    );
    const results = await Promise.all(promises);
    const project = results[0];
    const output = results[1].split("필요 산출물:")[1].trim();
    const service = results[2].split("서비스 요구사항:")[1].trim();
    let funcDesc = '';
    if (results[3] && results[3].includes("기능명세서:")) {
      funcDesc = results[3].split("기능명세서:")[1].trim();
    } else {
        // 예외 처리: 기능명세서가 없는 경우, 빈 문자열이나 기본 값을 설정
        funcDesc = '기능명세서가 없습니다.';
    }
    const selectIAQuery = 'SELECT * FROM ia WHERE ia_id = $1';
    const selectIAResult = await pool.query(selectIAQuery, [userId]);

    // 레코드가 이미 존재하면, 해당 레코드 삭제
    if (selectIAResult.rows.length > 0) {
      const deleteQuery = 'DELETE FROM ia WHERE ia_id = $1';
      await pool.query(deleteQuery, [userId]);
    }
     // parseLogData 함��는 로그 데이터를 파싱하는 가상의 함수입니다.

    const contentLines = project.split('\n'); // 내용을 줄 단위로 분리
    const projectInfo = {};
    let currentSection = '';
    contentLines.forEach(line => {
      // 각 섹션 제목을 확인하여 currentSection 업데이트
      if (line.includes('프로젝트 이름:') || line.includes('프로젝트 예산:') ||
          line.includes('프로젝트 기간:')) {
          let [key, value] = line.split(':').map(part => part.trim());
          projectInfo[key] = value; // 섹션 제목 다음에 오는 내용만 저장
          currentSection = ''; // 섹션 제목을 처리한 후 currentSection 초기화
      } else if (line.startsWith('작업분해구조(WBS):')) {
        currentSection = '작업분해구조(WBS)'; // 현재 섹션을 '작업분해구조(WBS)'로 업데이트
        projectInfo[currentSection] = ''; // 내용을 담을 빈 문자열 할당
      } else if (currentSection) {
          // 현재 섹션의 내용 추가 (여기서 '\n'은 필요에 따라 추가하거나 생략할 수 있음)
          projectInfo[currentSection] += (projectInfo[currentSection] ? '\n' : '') + line.trim();
      }
  });
    Object.keys(projectInfo).forEach(key => {
      // 값의 끝에 위치한 콤마를 제거합니다. 정규 표현식을 사용해 콤마와 공백을 처리합니다.
      projectInfo[key] = projectInfo[key].replace(/,\s*$/, '');
  });
  const agencyMapping = {
    '1': '영상/사진',
    '2': '브랜딩',
    '3': '앱 개발',
    '4': '웹 개발',
    '5': '디자인',
    '6': '마케팅',
    '7': '번역/통역',
    '8': '컨설팅',
  };
  const wbs_doc = projectInfo['작업분해구조(WBS)'];
  const proAgencyText = row.pro_agency.split(',')
                              .map(number => agencyMapping[number])
                              .join('/');
    const query = `
      INSERT INTO rfp(pro_name, pro_budget, pro_period, pro_service, pro_output, pro_reference, pro_ia, pro_wbs, user_session, expected_budget,expected_period, pro_agency, user_id,pro_funcdesc,wbs_doc)
      VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,$14,$15)
      ON CONFLICT (user_session) DO UPDATE SET
        pro_name = EXCLUDED.pro_name,
        pro_budget = EXCLUDED.pro_budget,
        pro_period = EXCLUDED.pro_period,
        pro_service = EXCLUDED.pro_service,
        pro_output = EXCLUDED.pro_output,
        pro_reference = EXCLUDED.pro_reference,
        pro_ia = EXCLUDED.pro_ia,
        pro_wbs = EXCLUDED.pro_wbs,
        expected_budget = EXCLUDED.expected_budget,
        expected_period = EXCLUDED.expected_period,
        pro_agency = EXCLUDED.pro_agency,
        user_id = EXCLUDED.user_id,
        pro_funcdesc = EXCLUDED.pro_funcdesc,
        wbs_doc = EXCLUDED.wbs_doc
    `;
    const values = [
      projectInfo['프로젝트 이름'],
      projectInfo['프로젝트 예산'], // "4500만원"에서 숫자만 추출
      projectInfo['프로젝트 기간'], // "5개월"에서 숫자만 추출
      service,
      output,
      row.pro_reference, // 배열을 문자열로 변환
      userId,
      // "기능명세서" 및 "작업분해구조(WBS)" 처리 로직 추가 필요
      userId,
      userId, // user_session에 userId를 사용
      row.pro_budget,
      row.pro_period,
      proAgencyText,
      req.session.userInfo.userId,
      funcDesc,
      wbs_doc
    ];
    try {
      const res = await pool.query(query, values);
    } catch (err) {
      console.error('Error executing query', err.stack);
    }
    const parsedData = parseAndInsertData(funcDesc,userId);
    const wbsItems = projectInfo['작업분해구조(WBS)'].split('-').map(item => item.trim()).filter(item => item);
    const insertWBSQuery = `
    INSERT INTO wbs (wbs_id, task_name, roles_involved, start_month, end_month, description)
    VALUES ($1, $2, $3, $4, $5, $6) 
    `;
    const selectQuery = 'SELECT * FROM wbs WHERE wbs_id = $1';
    const selectResult = await pool.query(selectQuery, [userId]);

    // 레코드가 이미 존재하면, 해당 레코드 삭제
    if (selectResult.rows.length > 0) {
      const deleteQuery = 'DELETE FROM wbs WHERE wbs_id = $1';
      await pool.query(deleteQuery, [userId]);
    }
    // values 배열을 위에서 추출한 정보로 채워 넣고 쿼리 실행
    // 각 wbsItems 항목에 대해 반복 실행 필요
  // wbsItems 항목에 대해 실행
    wbsItems.forEach(async (item, index) => {
      const [taskDetail, duration] = item.split(':').map(part => part.trim());
      const [taskName, roles] = taskDetail.split('(').map(part => part.trim().replace(')', ''));
      const [startMonth, endMonth] = duration.split('~').map(part => parseFloat(part.replace('개월', '').trim()));
      const wbsId = userId;
      const wbsValues = [
        userId, // 여기서는 단순히 순서를 나타내는 index를 사용했습니다. 실제 상황에서는 적절한 식별자를 사용해야 합니다.
        taskName,
        roles,
        startMonth,
        endMonth,
        '' // description이 없으므로 빈 문자열 사용
      ];
      try {
        // 먼저 해당 wbs_id(userId)에 대한 레코드가 있는지 확인
        // 새로운 레코드 삽입
        const insertQuery = `
          INSERT INTO wbs (wbs_id, task_name, roles_involved, start_month, end_month, description)
          VALUES ($1, $2, $3, $4, $5, $6)
        `;
        await pool.query(insertQuery, wbsValues);
    
      } catch (err) {
        console.error('Error processing WBS item', err.stack);
      }
    });
    
    } catch (error) {
      console.error('AI호출 오류', error);
    }
    res.json({ message: 'functionNumbers updated successfully' });
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).send('Server error');
  }
});

app.post('/signup', async (req, res) => {
  const { username, password, phoneNumber, email } = req.body;

  try {
    // 먼저 휴대폰 번호로 등록된 계정이 있는지 검사
    const checkPhoneQuery = 'SELECT user_id FROM user_info WHERE user_phone = $1';
    const { rows } = await pool.query(checkPhoneQuery, [phoneNumber]);

    // 휴대폰 번호가 이미 사용 중이라면 에러 메시지를 보냄
    if (rows.length > 0) {
      return res.status(409).send({ message: '해당 휴대폰 번호로 등록된 아이디가 존재합니다.' });
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // 휴대폰 번호가 중복되지 않는 경우, 회원 정보를 데이터베이스에 삽입
    const insertQuery = `
      INSERT INTO user_info (user_id, user_password, user_phone, user_email, subscription_status, subscription_new,billing_key,customer_key)
      VALUES ($1, $2, $3, $4,'N','N','N',$1)
    `;
    await pool.query(insertQuery, [username, hashedPassword, phoneNumber, email]);

    // 회원가입 성공 응답 전송
    res.status(201).send({ message: '회원가입 성공', userInfo: req.body });
  } catch (err) {
    console.error('Error processing signup item', err.stack);
    res.status(500).send({ message: '회원가입 처리 중 오류가 발생했습니다.' });
  }
});


app.get('/check-username', async (req, res) => {
  const { username } = req.query;
  // 데이터베이스에서 아이디 검사
  const user = await pool.query('SELECT user_id FROM user_info WHERE user_id = $1', [username]);
  if (user.rows.length > 0) {
      res.json({ isAvailable: false });
  } else {
      res.json({ isAvailable: true });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
      // user_info 테이블에서 user_id를 검사하는 쿼리
      const query = 'SELECT * FROM user_info WHERE user_id = $1';
      const { rows } = await pool.query(query, [username]);

      if (rows.length > 0) {
          const user = rows[0];

          // 비밀번호 비교
          const isPasswordMatch = await bcrypt.compare(password, user.user_password);

          if (isPasswordMatch) {
              // 비밀번호가 일치하면 로그인 성공
              req.session.userInfo = {
                userId: user.user_id,
                loginTime: new Date()
            };
            req.session.save(err => {
                if (err) {
                    console.error(err);
                    return res.status(500).send('Internal Server Error');
                }
                res.send({ message: '로그인 성공', userInfo: req.session.userInfo });
            });
          } else {
              // 비밀번호가 일치하지 않으면 로그인 실패
              res.status(401).send({ message: '잘못된 아이디 또는 비밀번호' });
          }
      } else {
          // 해당 아이디가 없으면 로그인 실패
          res.status(401).send({ message: '잘못된 아이디 또는 비밀번호' });
      }
  } catch (error) {
      console.error('로그인 처리 중 에러 발생:', error);
      res.status(500).send({ message: '서버 에러 발생' });
  }
});

app.get('/protected', (req, res) => {
  if (!req.session.userInfo) {
    return res.status(401).json({ message: 'Unauthorized', isLoggedIn: false });
  }
  res.json({ isLoggedIn: true, data: 'Protected data' });
});

app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Failed to log out');
    }
    res.send({ message: 'Logout successful' });
  });
});

app.get('/proposals', async (req, res) => {
  try {
    const user_id = req.session.userInfo.userId;
    const query = 'SELECT user_session AS id, pro_name AS title,pro_period AS period, pro_budget AS budget,pro_agency AS agency FROM rfp where user_id = $1 order by rfp_seq desc';
    const { rows } = await pool.query(query,[user_id]);
    res.json({ proposals: rows });
  } catch (error) {
    console.error('Database query error', error);
    res.status(500).send('Internal Server Error');
  }
});

app.post('/setProjectDetail', async (req, res) => {
  try {
      const { id } = req.body;
      const { rows } = await pool.query('SELECT pro_name, pro_budget, pro_period, pro_service, pro_output, expected_budget,expected_period, pro_agency, pro_reference FROM rfp WHERE user_session = $1;',[id]);
      const parsedRows = rows.map(row => {
        // pro_service 필드의 내용을 줄별로 분리합니다.
        const services = row.pro_service.split(',\n');
        
        // 각 줄에서 끝에 있는 콤마를 제거하고, 다시 줄바꿈 문자로 합칩니다.
        const parsedProService = services.map(service => service.trim()).join('\n');
        
        // 수정된 pro_service로 객체를 업데이트합니다.
        return { ...row, pro_service: parsedProService };
      });
      res.json(parsedRows);
  } catch (error) {
      res.status(500).send('Server error while fetching project info.');
  }
});

app.post('/setIADetail', async (req, res) => {
  try {
    const { id } = req.body;
      const { rows } = await pool.query('SELECT depth1,depth2,depth3,depth4 FROM ia WHERE ia_id = $1 order by ia_num asc,ia_seq asc;',[id]);

      const depth1Counts = rows.reduce((acc, cur) => {
        acc[cur.depth1] = (acc[cur.depth1] || 0) + 1;
        return acc;
      }, {});
      
      // depth2의 유니크한 조합을 체크하기 위한 객체
      const depth2Unique = {};
      const depth3Unique = {};

      rows.forEach(row => {
        if (row.depth2 !== '-') {
          const key = `${row.depth1}-${row.depth2}`;
          depth2Unique[key] = (depth2Unique[key] || 0) + 1;
        }
        if (row.depth3 !== '-') {
          const key = `${row.depth1}-${row.depth2}-${row.depth3}`;
          depth3Unique[key] = (depth3Unique[key] || 0) + 1;
        }
      });

      const filteredRows = rows.filter(row => {
        // depth1만 존재하고 그것이 유일한 경우 유지
        if (row.depth2 === '-' && depth1Counts[row.depth1] === 1) return true;

        // depth2가 있고, 해당 depth2가 유니크한 경우(다른 행에 동일한 depth2가 존재하지 않는 경우) 유지
        if (row.depth2 !== '-' && row.depth3 === '-' && depth2Unique[`${row.depth1}-${row.depth2}`] === 1) return true;

        // depth3가 있고, 해당 depth3가 유니크한 경우(다른 행에 동일한 depth3가 존재하지 않는 경우) 유지
        if (row.depth3 !== '-' && row.depth4 === '-' && depth3Unique[`${row.depth1}-${row.depth2}-${row.depth3}`] === 1) return true;

        // depth4가 있는 경우 모두 유지
        if (row.depth4 !== '-') return true;

        // 위 조건에 해당하지 않는 행은 필터링
        return false;
      });

      res.json(filteredRows);
  } catch (error) {
      res.status(500).send('Server error while fetching project info.');
  }
});

app.post('/setWbsDetail', async (req, res) => {
  try {
      const { id } = req.body;
      const { rows } = await pool.query('SELECT wbs_id, task_name, roles_involved, start_month, end_month FROM wbs WHERE wbs_id = $1 order by start_month asc,end_month asc;',[id]);
      res.json(rows);
  } catch (error) {
      res.status(500).send('Server error while fetching project info.');
  }
});

app.post('/getFuncDesc', async (req, res) => {
  try {
      const { id } = req.body;
      const { rows } = await pool.query('SELECT pro_funcdesc,pro_service,pro_output,wbs_doc from rfp where user_session = $1',[id]);
      res.json(rows);
  } catch (error) {
      res.status(500).send('Server error while fetching project info.');
  }
});

app.delete('/deleteProposal', async (req, res) => {
  const { id } = req.body; // 요청 바디에서 ID 추출
  
  try {
    // PostgreSQL 트랜잭션 시작
    await pool.query('BEGIN');

    // ia 테이블에서 데이터 삭제
    await pool.query('DELETE FROM ia WHERE ia_id = $1', [id]);

    // wbs 테이블에서 데이터 삭제
    await pool.query('DELETE FROM wbs WHERE wbs_id = $1', [id]);

    // rfp 테이블에서 데이터 삭제
    await pool.query('DELETE FROM rfp WHERE user_session = $1', [id]);

    // 트랜잭션 커밋
    await pool.query('COMMIT');

    res.send('Deletion successful');
  } catch (error) {
    // 트랜잭션 롤백
    await pool.query('ROLLBACK');
    console.error('Deletion failed:', error);
    res.status(500).send('Deletion failed');
  }
});

// app.post('/send-code', (req, res) => {
//   const { phoneNumber } = req.body;
//   const verificationCode = Math.floor(100000 + Math.random() * 900000); // 6자리 코드 생성

//   messageService.send({
//     'to': phoneNumber,
//     'from': '01057788443',
//     'text': `인증키 : ${verificationCode}.`
//   });

// });
const messageService = new solapi.SolapiMessageService("NCSQ4HNGSWYWO8GE", "LLWROXRDNQA1USFHGRSP1ZPQI0H6TC8Z");
const verificationCodes = new Map();
app.post('/send-code', (req, res) => {
  const { phoneNumber } = req.body;
  const verificationCode = Math.floor(100000 + Math.random() * 900000); // 6자리 코드 생성

  messageService.send({
    'to': phoneNumber,
    'from': '010-5778-8443',
    'text': `인증키 : ${verificationCode}`
  });
  verificationCodes.set(phoneNumber, verificationCode.toString());
  res.status(200).send({ message: 'Verification code sent successfully' });
});
app.post('/verify-code', (req, res) => {
  const { phoneNumber, verificationCode } = req.body;
  const savedCode = verificationCodes.get(phoneNumber);

  if (savedCode === verificationCode) {
    verificationCodes.delete(phoneNumber); // 인증 후 코드 삭제
    res.status(200).send({ message: 'Phone number verified successfully' });
  } else {
    res.status(400).send({ message: 'Invalid verification code' });
  }
});

app.post('/find-id', async (req, res) => {
  const { phoneNumber } = req.body;

  try {
    // 전화번호를 사용하여 user_id 조회
    const query = 'SELECT user_id FROM user_info WHERE user_phone = $1';
    const { rows } = await pool.query(query, [phoneNumber]);
    if (rows.length > 0) {
      // 전화번호에 해당하는 user_id가 있을 경우
      res.json({ username: rows[0].user_id });
    } else {
      // user_id를 찾을 수 없는 경우
      res.status(404).json({ message: '등록된 사용자가 없습니다.' });
    }
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ message: 'Server error while retrieving user ID.' });
  }
});

app.post('/find-pw', async (req, res) => {
  const { phoneNumber,username } = req.body;

  try {
    // 전화번호를 사용하여 user_id 조회
    const query = 'SELECT user_id,user_password,user_email FROM user_info WHERE user_phone = $1 and user_id = $2';
    const { rows } = await pool.query(query, [phoneNumber,username]);
    if (rows.length === 0) {
      return res.status(404).send({ message: '등록된 사용자가 없습니다.' });
    }
    const user = rows[0];
    const mailOptions = {
      from: process.env.EMAIL_USERNAME,  // 발신자 주소
      to: user.user_email,               // 수신자 주소
      subject: '프로메테우스 패스워드 전달', // 메일 제목
      text: `${user.user_id}님, 비밀번호는 ${user.user_password} 입니다.`  // 메일 내용
    };
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Send Mail error:', error);
        return res.status(500).send({ message: '이메일 전송 실패' });
      }
      res.status(200).send({ message: '비밀번호가 등록하신 이메일로 전송되었습니다.', password: rows[0].user_password  });
    });
  } catch (error) {
    console.error('Database or server error:', error);
    res.status(500).send({ message: '서버 에러 발생' });
  }
});

app.get('/auth/kakao/callback', async (req, res) => {
  try {
    const code = req.query.code;
    const tokenResponse = await axios.post('https://kauth.kakao.com/oauth/token', null, {
      params: {
        grant_type: 'authorization_code',
        client_id: '1f19c83bb96331acbdbfdabb55762e7d', // 카카오 개발자 콘솔에서 받은 REST API 키
        redirect_uri: `${process.env.URL}/auth/kakao/callback`,
        code: code,
      },
    });

    const accessToken = tokenResponse.data.access_token;

    const userResponse = await axios.get('https://kapi.kakao.com/v2/user/me', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    const userInfo = userResponse.data;

    req.session.userInfo = userInfo;

    // 여기에서 세션을 생성하거나, JWT 토큰을 발급할 수 있습니다.
    // 예시: req.session.user = userInfo;
    // 예시: const token = jwt.sign(userInfo, 'your_jwt_secret_key');
    
    // 클라이언트로 토큰을 보내거나, 로그인 성공 시 리다이렉트 처리
    res.redirect(`${process.env.URL}/init?token=${accessToken}`);

  } catch (error) {
    console.error('카카오 로그인 실패:', error);
    res.status(500).send('로그인 실패');
  }
});






app.get('/subscriptionNew', async (req, res) => {
  try {
    const user_id = req.session.userInfo.userId;
    const query = 'SELECT subscription_new FROM user_info WHERE user_id = $1';
    const { rows } = await pool.query(query, [user_id]);

    if (rows.length > 0) {
      res.json({ subscription_new: rows[0].subscription_new });
    } else {
      res.status(404).send('User not found');
    }
  } catch (error) {
    console.error('Database query error', error);
    res.status(500).send('Internal Server Error');
  }
});



app.post('/dalle-edit', upload.single('image'), async (req, res) => {
  const { prompt } = req.body;
  const imagePath = req.file.path;
  try {
    const maskPath = '/home/user/upload/sample-mask.png';
    console.log(`Using mask at: ${maskPath}`);

    // 마스크 이미지가 올바른지 확인
    if (!fs.existsSync(maskPath)) {
      throw new Error('Mask image not found');
    }

    // API 호출 및 응답 확인
    const image = await dalle(imagePath, prompt, maskPath);
    console.log('API response:', image);

    if (image.data && image.data.length > 0) {
      const editedImageUrl = image.data[0].url;

      // 편집된 이미지 다운로드
      const editedImageResponse = await axios.get(editedImageUrl, { responseType: 'arraybuffer' });
      const base64EditedImage = Buffer.from(editedImageResponse.data, 'binary').toString('base64');

      res.json({ base64Image: base64EditedImage });
    } else {
      throw new Error('No edited image returned from API');
    }
  } catch (error) {
    console.error('Error editing image:', error);
    res.status(500).json({ error: 'Failed to edit image' });
  } finally {
    fs.unlinkSync(imagePath);
  }
});

async function dalle(imagePath, prompt, maskPath) {
  const image = await openai.images.edit({
    image: fs.createReadStream(imagePath),
    mask: fs.createReadStream(maskPath),
    prompt: prompt,
    size: '1024x1024',
    n:3 
  });
  return image;
}



const getUserInfoFromNaver = (accessToken) => {
  return fetch('https://openapi.naver.com/v1/nid/me', {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    }
  })
  .then(response => response.json());
};


async function fetchAndCheck(recognizedText, threadId) {
    let isDifferent = false;
    let content = null;
    
    while (!isDifferent) {
      try {
        const messagesResponse = await openai.beta.threads.messages.list(threadId);
        let latestContent = null;
        if(messagesResponse.body.data[0].content[0]!=null){
          latestContent = messagesResponse.body.data[0].content[0].text.value;
        }
        // recognizedText와 최신 content가 다른지 확인
        if (recognizedText !== latestContent && latestContent !==null) {
          isDifferent = true;
          content = latestContent; // 새로운 content 값 저장
          break; 
        } else {
          // recognizedText와 최신 content가 같다면, 잠시 대기 후 다시 확인
          await new Promise(resolve => setTimeout(resolve, 1000));
        }
      } catch (error) {
        console.error('Error fetching messages:', error);
        break; 
      }
    }
    
    return content; // 새로운 content 반환, null이면 변경된 내용이 없는 경우
  }

  async function gptsApi(output, gptKey, userId) {
    const assistant = await openai.beta.assistants.retrieve(
      // "asst_KCYb2t4bp7fCJSvvMfOZGcZ4"
      gptKey
    );
    
    const thread = await openai.beta.threads.create();

    await openai.beta.threads.messages.create(thread.id, {
    role: "user",
    content: output
    });

    const run = await openai.beta.threads.runs.create(thread.id, {
    assistant_id: assistant.id,
    instructions: "",
    });

    await checkRunStatus(openai,thread.id,run.id);

    try {
      await pool.query(
        'INSERT INTO thread_id (thread_id, user_session) VALUES ($1, $2) ON CONFLICT (user_session) DO UPDATE SET thread_id = EXCLUDED.thread_id RETURNING *',
        [run.thread_id, userId]
      );
      // 다른 데이터베이스 작업 수행
    } catch (error) {
      console.error('Database query error:', error);
    }

    const queryResult = await pool.query(
    'SELECT thread_id FROM thread_id WHERE user_session = $1;',
    [userId] // $1에 해당하는 user_session 값으로 ip 변수 사용
    );
    const message = await openai.beta.threads.messages.list(thread.id);
    const contents = message.body.data[0].content[0].text.value;

    return contents;
  }

  async function parseAndInsertData(logData, userId) {
    // 줄별로 데이터를 분리
    const lines = logData.split("\n");
    let depthContents = ["", "", "", "", ""]; // depthContents 배열을 5개 요소로 확장

    for (const line of lines) { // forEach 대신 for...of 사용하여 비동기 처리 보장
        // 깊이 판별 (마침표 개수로 결정)
        const depth = (line.match(/\./g) || []).length;

        // 최상위 깊이 번호 추출 (첫 번째 숫자)
        const topLevelNumber = line.match(/^\s*(\d+)/)?.[1] ?? "";

        // 실제 내용 추출 (숫자와 마침표 제거 후 앞뒤 공백 제거)
        let content = line.replace(/^\s*\d+(\.\d+)*\.\s*/, "").trim();

        // 상위 depth의 내용을 유지하면서 현재 깊이의 내용 업데이트
        depthContents = depthContents.map((c, index) => {
            if (index === 0) return topLevelNumber; // 첫 번째 요소에는 최상위 깊이 번호 저장
            return index === depth ? content : (index < depth ? c : "-");
        });
        if (depthContents.join('') === '' || depthContents.every(dc => dc === "-" || dc === "")) {
          continue;
        }
        await insertIntoIaTable(depthContents, userId); // 실제 삽입 로직을 호출
    }
}


  async function insertIntoIaTable(depthContents, userId) {
    
    const query = `
      INSERT INTO ia (ia_id, ia_num, depth1, depth2, depth3, depth4)
      VALUES ($1, $2, $3, $4, $5, $6)
    `;
    const values = [userId, ...depthContents];
    try {
      const res = await pool.query(query, values);
    } catch (err) {
      console.error('Insertion error:', err);
    }
  }
  
  async function checkRunStatus(client, threadId, runId) {
    let run = await client.beta.threads.runs.retrieve(threadId, runId);
    while (run.status !== "completed") {
        await new Promise(resolve => setTimeout(resolve, 1000)); // 1초 대기
        run = await client.beta.threads.runs.retrieve(threadId, runId);
    }
}

const secretKey = process.env.TOSS_SECRET_KEY;
app.post('/payment/success', async (req, res) => {
  const { orderId, paymentKey, amount } = req.body;
  console.log(paymentKey);
  try {
    // Toss Payments API에 결제 승인 요청
    const response = await axios.post('https://api.tosspayments.com/v1/payments/confirm', {
      orderId,
      paymentKey,
      amount,
    }, {
      headers: {
        Authorization: `Basic ${Buffer.from(`${secretKey}:`).toString('base64')}`, // 시크릿 키를 Base64 인코딩하여 설정
        'Content-Type': 'application/json',
      },
    });

    // 결제 승인 후 데이터베이스에 저장하거나 필요한 후속 작업 처리
    // 예: 사용자 구독 상태 업데이트, 결제 정보 저장 등

    res.send({ success: true, data: response.data });
  } catch (error) {
    console.error('결제 승인 오류:', error.response.data);
    res.status(400).send({ success: false, message: error.response.data.message });
  }
});

app.get('/subscription', async (req, res) => {
  try {
    const userId = req.session.userInfo.userId; // 사용자 ID를 세션에서 가져옵니다.
    const query = `
      SELECT subscription_status, subscription_start_date, subscription_end_date, available_num 
      FROM user_info 
      WHERE user_id = $1
    `;
    const { rows } = await pool.query(query, [userId]);

    if (rows.length > 0) {
      res.json(rows[0]);
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  } catch (err) {
    console.error('Error fetching subscription data:', err);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.get('/payment-history', async (req, res) => {
  try {
    const userId = req.session.userInfo.userId; // 클라이언트에서 user_id를 쿼리 파라미터로 전달한다고 가정합니다.

    if (!userId) {
      return res.status(400).json({ message: 'user_id is required' });
    }

    const result = await pool.query(
      'SELECT date, plan, amount, method, status, receipt_url FROM payment_history WHERE user_id = $1 ORDER BY date DESC',
      [userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching payment history:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/save-billing-key', async (req, res) => {
  const { billingKey, customerKey } = req.body;
  console.log('123');

  if (!billingKey || !customerKey) {
    return res.status(400).json({ success: false, message: 'Invalid request data' });
  }

  try {
    const queryText = 'UPDATE user_info SET billing_key = $1 WHERE customer_key = $2';
    await db.query(queryText, [billingKey, customerKey]);

    res.status(200).json({ success: true, message: 'Billing key saved successfully' });
  } catch (error) {
    console.error('Error saving billing key:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/get-customer-key', (req, res) => {
  if (req.session && req.session.userInfo.userId) {
    res.json({ customerKey: req.session.userInfo.userId });
  } else {
    res.status(401).json({ error: 'User not authenticated' });
  }
});




const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {    // '0.0.0.0'으로 모든 IP에서 접근 가능하도록 수정
    console.log(`Server running on port ${PORT}`);
});
