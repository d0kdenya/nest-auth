import { Module } from '@nestjs/common';
import { UserModule } from './user/user.module';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { ConfigModule } from '@nestjs/config';
import { JwtAuthGuard } from './auth/guards/jwt.auth.guard';
import { APP_GUARD } from '@nestjs/core';
import { RolesGuard } from './auth/guards/roles.guard';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    UserModule,
    PrismaModule,
    AuthModule
  ],
  controllers: [],
  providers: [{
    provide: APP_GUARD,
    useClass: JwtAuthGuard
  }, {
    provide: APP_GUARD,
    useClass: RolesGuard
  }],
})
export class AppModule {}
