import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { UserModule } from '../user/user.module';
import { options } from './config/jwt.module.async.options';
import { JwtStrategy } from './strategies/jwt.strategy';
import { GoogleStrategy } from './strategies/google.startegy';
import { HttpModule } from '@nestjs/axios';
import { YandexStrategy } from './strategies/yandex.strategy';

@Module({
  imports: [
    JwtModule.registerAsync(options()),
    PassportModule,
    UserModule,
    HttpModule
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy, GoogleStrategy, YandexStrategy]
})
export class AuthModule {}
