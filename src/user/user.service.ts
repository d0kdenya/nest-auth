import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { User } from '@prisma/client';
import { genSalt, hash } from 'bcrypt';

@Injectable()
export class UserService {
  constructor(private readonly prismaService: PrismaService) {}

  async save(user: Partial<User>) {
    return this.prismaService.user.create({
      data: {
        email: user.email,
        password: await this.hashPassword(user.password),
        roles: ['USER']
      }
    })
  }

  async findOne(idOrEmail: string) {
    return this.prismaService.user.findFirst({
      where: {
        OR: [
          { id: idOrEmail },
          { email: idOrEmail }
        ]
      }
    })
  }

  async delete(id: string) {
    return this.prismaService.user.delete({
      where: { id },
      select: { id: true }
    })
  }

  private async hashPassword(password: string): Promise<string> {
    return await hash(password, await genSalt(12));
  }
}
