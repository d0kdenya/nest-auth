import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { JwtPayload } from '../../../../src/auth/interfaces/tokens.interface';

export const CurrentUser = createParamDecorator((key: keyof JwtPayload, ctx: ExecutionContext): JwtPayload | Partial<JwtPayload> => {
  const request = ctx.switchToHttp().getRequest()
  return key ? request.user[key] : request.user
})