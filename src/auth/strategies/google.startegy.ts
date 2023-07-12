import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-google-oauth20';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(private readonly configService: ConfigService) {
    super({
      clientID: configService.get('GOOGLE_CLIENT_ID'),               // Google Cloud Console
      clientSecret: configService.get('GOOGLE_CLIENT_SECRET'),       // Google Cloud Console
      callbackURL: 'http://localhost:3000/api/auth/google/callback', // Callback URL (куда будет перенаправлен ответ)
      scope: ['email', 'profile']                                    // Что необходимо вернуть пользователю при авторизации
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile,
    done: (err: any, user: any, info?: any) => void
  ): Promise<any> {
    const { name, emails, photos } = profile
    const user = {
      email: emails[0].value,
      firstName: name.givenName,
      lastName: name.familyName,
      picture: photos[0].value,
      accessToken
    }
    done(null, user)
  }
}