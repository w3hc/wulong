import { Module } from '@nestjs/common';
import { DstackV1Client } from '../keys/dstack-v1.client';
import { TeeTlsService } from './tee-tls.service';

@Module({
  providers: [DstackV1Client, TeeTlsService],
  exports: [TeeTlsService],
})
export class TlsModule {}
