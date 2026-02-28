import { Controller, Get, Param } from '@nestjs/common';
import { UsersService } from './users.service';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get(':id')
  getMyUser(@Param() params: { id: string }) {
    const { id } = params;

    return this.usersService.getMyUser(id);
  }

  @Get()
  getUsers() {
    return this.usersService.getUsers();
  }
}
