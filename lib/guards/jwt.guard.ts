import * as express from 'express';
import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '..';
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
        const tokenHeader = req.header('Authorization').split(' ');
        if (tokenHeader.length !== 2) {
            throw new UnauthorizedException();
        }

        try {
            await this.jwtService.validateToken(tokenHeader[1]);

            const claims = await this.jwtService.decodeToken(tokenHeader[1]);
            for (const property in claims) {
                if (claims.hasOwnProperty(property)) {
                    req.headers[`token-claim-${property}`] = claims[property];
                }
            }
        } catch (e) {
            throw new UnauthorizedException();
        }

        return true;
    }
}