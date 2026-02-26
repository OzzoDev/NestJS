import { BadRequestException, Injectable } from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async signup(dto: AuthDto) {
    const { email, password } = dto;

    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      throw new BadRequestException('Email already exists');
    }

    const hashedPassword = await this.hashPassword(password);

    await this.prisma.user.create({
      data: {
        email,
        hashedPassword,
      },
    });

    return { message: 'signup was successful' };
  }

  async signin(dto: AuthDto) {
    const { email, password } = dto;

    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!existingUser) {
      throw new BadRequestException('Wrong credentials');
    }

    const isMatch = await this.comparePassword({
      password,
      hash: existingUser.hashedPassword,
    });

    if (!isMatch) {
      throw new BadRequestException('Wrong credentials');
    }

    return { message: 'signin was successful' };
  }

  async signout() {
    return '';
  }

  async hashPassword(passowrd: string) {
    return await bcrypt.hash(passowrd, 10);
  }

  async comparePassword(args: { password: string; hash: string }) {
    const { password, hash } = args;

    return await bcrypt.compare(password, hash);
  }
}
