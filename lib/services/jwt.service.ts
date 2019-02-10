import * as jwt from 'jsonwebtoken';
import * as fs from 'fs';
import { Injectable } from '@nestjs/common';

@Injectable()
export class JwtService {
    private readonly cert: Buffer;
    private readonly audiences: string[];
    private readonly issuers: string[];

    constructor() {
        const certPath = process.env.JWT_PUBLIC_KEY;
        if (!certPath) {
            throw new Error('You must provide JWT_PUBLIC_KEY environment variable');
        }
        if (!process.env.JWT_AUDIENCES) {
            throw new Error('You must provide JWT_AUDIENCES environment variable');
        }
        if (!process.env.JWT_ISSUER) {
            throw new Error('You must provide JWT_ISSUER environment variable');
        }

        this.audiences = process.env.JWT_AUDIENCES.split(' ');
        this.issuers = process.env.JWT_ISSUER.split(' ');

        try {
            this.cert = fs.readFileSync(certPath);
        } catch (e) {
            throw new Error('No public key found');
        }
    }

    public validateToken(token: string): Promise<boolean> {
        return new Promise<boolean>((resolve, reject) => {
            jwt.verify(token, this.cert, {
                audience: this.audiences,
                issuer: this.issuers
            }, err => {
                if (err) {
                    reject();
                }

                resolve(true);
            });
        });
    }

    public async decodeToken(token: string): Promise<object> {
        return jwt.decode(token, {
            json: true,
        }) as object;
    }
}
