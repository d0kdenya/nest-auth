import {
  Body,
  ClassSerializerInterceptor,
  Controller,
  Delete,
  Get,
  Param,
  ParseUUIDPipe,
  Post, Put, UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { UserService } from './user.service';
import { UserResponse } from './responses/user.response';
import { CurrentUser } from '@common/decorators/current-user.decorator';
import { JwtPayload } from '../auth/interfaces/tokens.interface';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '@common/decorators/roles.decorator';
import { Role, User } from '@prisma/client';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @UseGuards(RolesGuard)
  @Roles(Role.ADMIN)
  @Get()
  async me (@CurrentUser() user: JwtPayload) {
    return user
  }

  @UseInterceptors(ClassSerializerInterceptor)
  @Get(':idOrEmail')
  async findOneUser(@Param('idOrEmail') idOrEmail: string) {
    const user = await this.userService.findOne(idOrEmail)
    return new UserResponse(user)
  }

  @UseInterceptors(ClassSerializerInterceptor)
  @Post()
  async createUser(@Body() dto) {
    const user = await this.userService.save(dto)
    return new UserResponse(user)
  }

  @Delete(':id')
  async deleteUser(@Param('id', ParseUUIDPipe) id: string, @CurrentUser() user: JwtPayload) {
    return this.userService.delete(id, user)
  }

  @UseInterceptors(ClassSerializerInterceptor)
  @Put()
  async updateUser(@Body() body: Partial<User>) {
    const user = await this.userService.save(body)
    return new UserResponse(user)
  }
}
