import { Controller, Get, Post } from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post("signup")
  signup(){
    return "sign up route"
  }

  @Post("signin")
  signin(){
    return "sign in route"
  }

  @Get("signout")
  signout(){
    return "sign out route"
  }
}
