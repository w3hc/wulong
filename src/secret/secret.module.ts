import { Module } from '@nestjs/common';
import { SecretController } from './secret.controller';
import { SecretService } from './secret.service';
import { AuthModule } from '../auth/auth.module';
import { AttestationModule } from '../attestation/attestation.module';
import { MlKemEncryptionService } from '../encryption/mlkem-encryption.service';
import { KeysModule } from '../keys/keys.module';
import { TlsModule } from '../tls/tls.module';

@Module({
  imports: [AttestationModule, AuthModule, KeysModule, TlsModule],
  controllers: [SecretController],
  providers: [SecretService, MlKemEncryptionService],
})
export class SecretModule {}
