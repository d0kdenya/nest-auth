import { ForbiddenException, Inject, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { Provider, Role, User } from '@prisma/client';
import { genSalt, hash } from 'bcrypt';
import { JwtPayload } from '../auth/interfaces/tokens.interface';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { ConfigService } from '@nestjs/config';
import { convertToSecondsUtil } from '@common/utils/convert-to-seconds';
import { Cache } from 'cache-manager';

@Injectable()
export class UserService {
  constructor(
    @Inject(CACHE_MANAGER)
    private cacheManager: Cache,
    private readonly configService: ConfigService,
    private readonly prismaService: PrismaService
  ) {}

  async save(user: Partial<User>) {
    return this.prismaService.user.create({
      data: {
        email: user.email,
        password: user?.password ? await this.hashPassword(user.password) : null,
        roles: ['USER'],
        provider: user.provider
      }
    })
  }

  async findOne(idOrEmail: string, isReset = false) {
    if (isReset) {
      await this.cacheManager.del(idOrEmail)
    }
    const user = await this.cacheManager.get<User>(idOrEmail)

    if (!user) {
      const user = await this.prismaService.user.findFirst({
        where: {
          OR: [
            { id: idOrEmail },
            { email: idOrEmail }
          ]
        }
      })

      if (!user) {
        return null
      }

      await this.cacheManager.set(idOrEmail, user, convertToSecondsUtil(this.configService.get('JWT_EXP')))

      return user
    }
    return user
  }

  async delete(id: string, user: JwtPayload) {
    if (user.id !== id && !user.roles.includes(Role.ADMIN)) {
      throw new ForbiddenException()
    }
    await Promise.all([
      await this.cacheManager.del(id),
      await this.cacheManager.del(user.email)
    ])
    return this.prismaService.user.delete({
      where: { id },
      select: { id: true }
    })
  }

  private async hashPassword(password: string): Promise<string> {
    return await hash(password, await genSalt(12));
  }
}
