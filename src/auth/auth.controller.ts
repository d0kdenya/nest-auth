import {
  BadRequestException,
  Body, ClassSerializerInterceptor,
  Controller,
  Get,
  HttpStatus,
  Post, Query, Req,
  Res,
  UnauthorizedException, UseGuards, UseInterceptors,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { Tokens } from './interfaces/tokens.interface';
import { Response, Request } from 'express'
import { ConfigService } from '@nestjs/config';
import { Cookie } from '@common/decorators/cookies.decorator';
import { UserAgent } from '@common/decorators/user-agent.decorator';
import { Public } from '@common/decorators/public.decorator';
import { UserResponse } from '../user/responses/user.response';
import { GoogleGuard } from './guards/google.guard';
import { HttpService } from '@nestjs/axios';
import { map, mergeMap } from 'rxjs';
import { handleTimeoutAndErrors } from '@common/helpers/timeout-error.helper';
import { YandexGuard } from './guards/yandex.guard';
import { Provider } from '@prisma/client';

const REFRESH_TOKEN = 'refreshtoken'

@Public()
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
    private readonly httpService: HttpService
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

  @UseGuards(GoogleGuard)
  @Get('google')
  async googleAuth() {}

  @UseGuards(GoogleGuard)
  @Get('google/callback')
  async googleAuthCallback(
    @Req() req: Request,
    @Res() res: Response
  ) {
    const token = req.user['accessToken']
    return res.redirect(`http://localhost:3000/api/auth/success-google?token=${token}`)
  }

  @Get('success-google')
  async successGoogle(
    @Query('token') token: string,
    @UserAgent() agent: string,
    @Res() res: Response
  ) {
    return this.httpService
      .get(`https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=${token}`)
      .pipe(
        mergeMap(({ data: { email } }) =>
          this.authService.providerAuth(email, agent, Provider.GOOGLE)
        ),
        map(data => this.setRefreshTokenToCookies(data, res)),
        handleTimeoutAndErrors()
      )
  }

  @UseGuards(YandexGuard)
  @Get('yandex')
  async yandexAuth() {}

  @UseGuards(YandexGuard)
  @Get('yandex/callback')
  async yandexAuthCallback(
    @Req() req: Request,
    @Res() res: Response
  ) {
    const token = req.user['accessToken']
    return res.redirect(`http://localhost:3000/api/auth/success-yandex?token=${token}`)
  }

  @Get('success-yandex')
  async successYandex(
    @Query('token') token: string,
    @UserAgent() agent: string,
    @Res() res: Response
  ) {
    return this.httpService
      .get(`https://login.yandex.ru/info?format=json&oauth_token=${token}`)
      .pipe(
        mergeMap(({ data: { default_email } }) =>
          this.authService.providerAuth(default_email, agent, Provider.YANDEX)
        ),
        map(data => this.setRefreshTokenToCookies(data, res)),
        handleTimeoutAndErrors()
      )
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
