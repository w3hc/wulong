import { Module } from '@nestjs/common';
import { JsonRpcProvider } from 'ethers';
import { KeysModule } from '../keys/keys.module';
import { RELAYER_PROVIDER, RelayerService } from './relayer.service';

@Module({
  imports: [KeysModule],
  providers: [
    {
      provide: RELAYER_PROVIDER,
      useFactory: () =>
        process.env.BASE_RPC_URL
          ? new JsonRpcProvider(process.env.BASE_RPC_URL)
          : null,
    },
    RelayerService,
  ],
  exports: [RelayerService],
})
export class RelayerModule {}
