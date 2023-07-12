import { IsEmail, IsString, MinLength, Validate } from 'class-validator';
import { IsPasswordMatchingConstraint } from '@common/decorators/is-password-matching-constraint.decorator';

export class RegisterDto {
  @IsEmail()
  email: string

  @IsString()
  @MinLength(6)
  password: string

  @IsString()
  @MinLength(6)
  @Validate(IsPasswordMatchingConstraint)
  passwordRepeat: string
}