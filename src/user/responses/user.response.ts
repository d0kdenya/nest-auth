import { Provider, Role, User } from '@prisma/client';
import { Exclude } from 'class-transformer';

export class UserResponse implements User {
  id: string
  email: string
  updatedAt: Date
  roles: Role[]

  @Exclude()
  password: string

  @Exclude()
  createdAt: Date

  @Exclude()
  provider: Provider

  constructor(user: User) {
    Object.assign(this, user)
  }
}