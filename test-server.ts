import { NestFactory } from '@nestjs/core';
import { Module, Controller, Get, Post, Body, Session } from '@nestjs/common';
import { Pool } from 'pg';
import * as session from 'express-session';
import * as ConnectPgSimple from 'connect-pg-simple';
import { config } from 'dotenv';

// 환경변수 로드
config();

// DB 연결 설정
const pool = new Pool({
  user: 'postgres',
  host: process.env.DBURL,
  database: 'dev',
  password: process.env.DBPASSWORD,
  port: 5432,
  ssl: {
    rejectUnauthorized: false
  },
});

@Controller()
class AppController {
  @Get('protected')
  async protected(@Session() session: any) {
    if (!session.userInfo) {
      return { message: 'Unauthorized', isLoggedIn: false };
    }
    return { isLoggedIn: true, data: 'Protected data' };
  }

  @Get('subscription')
  async getSubscription(@Session() session: any) {
    try {
      const userId = session.userInfo?.userId;
      if (!userId) {
        return { message: 'User not authenticated' };
      }

      const { rows } = await pool.query(
        `SELECT subscription_status, subscription_start_date, subscription_end_date, available_num 
         FROM user_info 
         WHERE user_id = $1`,
        [userId]
      );

      return rows[0] || { message: 'User not found' };
    } catch (error) {
      console.error('Error:', error);
      return { message: 'Internal server error' };
    }
  }

  @Post('getFuncDesc')
  async getFuncDesc(@Body() body: { id: string }) {
    try {
      const { rows } = await pool.query(
        'SELECT pro_funcdesc,pro_service,pro_output,wbs_doc from rfp where user_session = $1',
        [body.id]
      );
      return rows;
    } catch (error) {
      console.error('Error:', error);
      return { message: 'Server error while fetching project info.' };
    }
  }

  @Get('health')
  health() {
    return { status: 'ok' };
  }
}

@Module({
  controllers: [AppController],
})
class AppModule {}

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  
  // CORS 설정
  app.enableCors({
    origin: ['https://app.metheus.pro', 'http://localhost:3000'],
    credentials: true,
  });

  // 세션 설정
  const PgSession = ConnectPgSimple(session);
  app.use(
    session({
      store: new PgSession({
        pool: pool,
        tableName: 'session'
      }),
      secret: 'secret key',
      resave: false,
      saveUninitialized: true,
      cookie: {
        maxAge: 3600000,
        secure: process.env.ENV === 'production',
        httpOnly: true,
        sameSite: 'none'
      }
    })
  );

  await app.listen(3001, '0.0.0.0');
  console.log('Server running on port 3001');
}

bootstrap();