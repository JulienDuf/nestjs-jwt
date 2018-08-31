import * as jwt from 'jsonwebtoken';
import * as fs from 'fs';
import { Injectable } from '@nestjs/common';

@Injectable()
export class JwtService {
    private readonly cert: Buffer;

    constructor() {
        const certPath = process.env.JWT_PUBLIC_KEY;
        if (!certPath) {
            throw new Error('You must provide JWT_PUBLIC_KEY environment variable');
        }

        try {
            this.cert = fs.readFileSync(certPath);
        } catch (e) {
            throw new Error('No public key found');
        }
    }

    public validateToken(token: string): Promise<boolean> {
        return new Promise<boolean>((resolve, reject) => {
            jwt.verify(token, this.cert, err => {
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