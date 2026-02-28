import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JWT_SECRET } from 'src/utils/constants';
import { Request, Response } from 'express';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
  ) {}

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

  async signin(dto: AuthDto, req: Request, res: Response) {
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

    const token = await this.signToken({
      id: existingUser.id,
      email: existingUser.email,
    });

    if (!token) {
      throw new ForbiddenException();
    }

    res.cookie('token', token);

    return res.send({ message: 'login successful' });
  }

  async signout(req: Request, res: Response) {
    res.clearCookie('token');
    return res.send({ message: 'logout successful' });
  }

  async hashPassword(passowrd: string) {
    return await bcrypt.hash(passowrd, 10);
  }

  async comparePassword(args: { password: string; hash: string }) {
    const { password, hash } = args;

    return await bcrypt.compare(password, hash);
  }

  async signToken(args: { id: string; email: string }) {
    const payload = args;

    return this.jwt.signAsync(payload, { secret: JWT_SECRET });
  }
}
