import { Module } from '@nestjs/common';
import { KeysModule } from '../keys/keys.module';
import { TeePlatformService } from './tee-platform.service';

@Module({
  imports: [KeysModule],
  providers: [TeePlatformService],
  exports: [TeePlatformService],
})
export class AttestationModule {}
