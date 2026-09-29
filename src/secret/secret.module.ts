import { Module } from '@nestjs/common';
import { SecretController } from './secret.controller';
import { SecretService } from './secret.service';
import { AuthModule } from '../auth/auth.module';
import { TeePlatformService } from '../attestation/tee-platform.service';
import { MlKemEncryptionService } from '../encryption/mlkem-encryption.service';
import { KeysModule } from '../keys/keys.module';

@Module({
  imports: [AuthModule, KeysModule],
  controllers: [SecretController],
  providers: [SecretService, TeePlatformService, MlKemEncryptionService],
})
export class SecretModule {}
