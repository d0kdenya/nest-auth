import {
  BadRequestException,
  Body, ClassSerializerInterceptor,
  Controller,
  Get,
  HttpStatus,
  Post,
  Res,
  UnauthorizedException, UseInterceptors,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { Tokens } from './interfaces/tokens.interface';
import { Response } from 'express'
import { ConfigService } from '@nestjs/config';
import { Cookie } from '@common/decorators/cookies.decorator';
import { UserAgent } from '@common/decorators/user-agent.decorator';
import { Public } from '@common/decorators/public.decorator';
import { UserResponse } from '../user/responses/user.response';

const REFRESH_TOKEN = 'refreshtoken'

@Public()
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService
  ) {}

  @UseInterceptors(ClassSerializerInterceptor)
  @Post('register')
  async register(@Body() dto: RegisterDto) {
    const user = await this.authService.register(dto)

    if (!user) {
      throw new BadRequestException(`Не пользучается зарегистрировать пользователя с данными: ${JSON.stringify(dto)}`)
    }
    return new UserResponse(user)
  }

  @Post('login')
  async login(
    @Body() dto: LoginDto,
    @Res() res: Response,
    @UserAgent() agent: string
  ) {
    const tokens = await this.authService.login(dto, agent)

    if (!tokens) {
      throw new BadRequestException(`Не получается войти с данными: ${JSON.stringify(dto)}`)
    }
    await this.setRefreshTokenToCookies(tokens, res)
  }

  @Get('logout')
  async logout(
    @Cookie(REFRESH_TOKEN) refreshToken: string,
    @Res() res: Response
  ) {
    if (!refreshToken) {
      return res.sendStatus(HttpStatus.OK)
    }
    await this.authService.deleteRefreshToken(refreshToken)
    res.cookie(REFRESH_TOKEN, '', {
      httpOnly: true,
      secure: true,
      expires: new Date()
    })
    res.sendStatus(HttpStatus.OK)
  }

  @Get('refresh')
  async refreshTokens(
    @Cookie(REFRESH_TOKEN) refreshToken: string,
    @Res() res: Response,
    @UserAgent() agent: string
  ) {
    if (!refreshToken) {
      throw new UnauthorizedException()
    }
    const tokens = await this.authService.refreshTokens(refreshToken, agent)

    if (!tokens) {
      throw new UnauthorizedException()
    }
    await this.setRefreshTokenToCookies(tokens, res)
  }

  private async setRefreshTokenToCookies(tokens: Tokens, res: Response) {
    if (!tokens) {
      throw new UnauthorizedException()
    }
    res.cookie(REFRESH_TOKEN, tokens.refreshToken.token, {
      httpOnly: true,         // Токен не будет доступен через JS на клиенте
      sameSite: 'lax',        // Все запросы должны отправляться с того же сайта
      expires: new Date(tokens.refreshToken.exp),
      secure: this.configService.get('NODE_ENV', 'development') === 'production',     // true - HTTPS
      path: '/',              // Где доступны куки
    })
    res.status(HttpStatus.CREATED).json({ accessToken: tokens.accessToken })
  }
}
