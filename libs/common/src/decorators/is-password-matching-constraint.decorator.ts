import { ValidationArguments, ValidatorConstraint, ValidatorConstraintInterface } from 'class-validator';
import { RegisterDto } from '../../../../src/auth/dto/register.dto';

@ValidatorConstraint({ name: 'IsPasswordsMatching', async: true })
export class IsPasswordMatchingConstraint implements ValidatorConstraintInterface {
  validate(passwordRepeat: string, args: ValidationArguments) {
    const obj = args.object as RegisterDto
    return obj.password === passwordRepeat
  }

  defaultMessage(validationArguments?: ValidationArguments): string {
    return 'Пароли не совпадают'
  }
}