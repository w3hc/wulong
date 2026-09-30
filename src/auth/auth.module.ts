import { Module } from '@nestjs/common';
import { SiweService } from './siwe.service';
import { SiweGuard } from './siwe.guard';
import { AuthController } from './auth.controller';
import { KeysModule } from '../keys/keys.module';

@Module({
  imports: [KeysModule],
  controllers: [AuthController],
  providers: [SiweService, SiweGuard],
  exports: [SiweService, SiweGuard],
})
export class AuthModule {}
