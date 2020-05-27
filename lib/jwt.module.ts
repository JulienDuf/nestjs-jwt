import { DynamicModule, Global, Module } from '@nestjs/common';
import { JwtService } from './services/jwt.service';
import { JwtConfigModel } from './models/config.model';
import { JWT_CONFIG } from './constant';

@Global()
@Module({
    providers: [
        JwtService,
    ],
    exports: [
        JwtService,
    ],
})
export class JwtModule {
    public static forRoot(config?: JwtConfigModel): DynamicModule {
        return {
            module: JwtModule,
            providers: [
                {
                    provide: JWT_CONFIG,
                    useValue: config,
                },
            ],
            exports: [JWT_CONFIG],
        };
    }
}
