import * as express from 'express';
import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '../services/jwt.service';
import { Reflector } from '@nestjs/core';

@Injectable()
export class JwtGuard implements CanActivate{
    constructor(private readonly reflector: Reflector,
                private readonly jwtService: JwtService) {
    }

    public async canActivate(context: ExecutionContext): Promise<boolean> {
        const publicRoute = this.reflector.get<boolean>('public-route', context.getHandler());
        if (publicRoute) {
            return true;
        }

        const req = context.switchToHttp().getRequest<express.Request>();
        const tokenHeader = req.header('Authorization');
        if (!tokenHeader) {
            throw new UnauthorizedException();
        }

        const tokens = tokenHeader.split(' ');
        if (tokens.length !== 2) {
            throw new UnauthorizedException();
        }

        try {
            await this.jwtService.validateToken(tokens[1]);

            const claims = await this.jwtService.decodeToken(tokens[1]);
            for (const property in claims) {
                if (claims.hasOwnProperty(property)) {
                    req.headers[`token-claim-${property}`] = claims[property];
                }
            }
        } catch (e) {
            throw new UnauthorizedException('', e.message);
        }

        return true;
    }
}
