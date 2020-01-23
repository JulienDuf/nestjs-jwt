import { JwtHeader, SigningKeyCallback } from 'jsonwebtoken';
import * as jwt from 'jsonwebtoken';
import * as jwksClient from 'jwks-rsa';
import * as fs from 'fs';
import { Injectable } from '@nestjs/common';

@Injectable()
export class JwtService {
    private readonly client: jwksClient.JwksClient;
    private readonly cert: Buffer;
    private readonly audiences?: string[];
    private readonly issuers: string[];

    constructor() {
        const certPath = process.env.JWT_PUBLIC_KEY;
        const jwksUri = process.env.JWKS_URI;
        if (!certPath && !jwksUri) {
            throw new Error('You must provide JWT_PUBLIC_KEY or JWKS_URI environment variable');
        }
        if (!process.env.JWT_ISSUER) {
            throw new Error('You must provide JWT_ISSUER environment variable');
        }

        this.audiences = process.env.JWT_AUDIENCES?.split(' ');
        this.issuers = process.env.JWT_ISSUER.split(' ');

        try {
            if (jwksUri) {
                this.client = jwksClient({
                    jwksUri,
                    cache: true,
                    rateLimit: true,
                    jwksRequestsPerMinute: 10,
                });
            } else {
                this.cert = fs.readFileSync(certPath);
            }
        } catch (e) {
            throw new Error('No public key found');
        }
    }

    public validateToken(token: string): Promise<boolean> {
        const certOrGetKey = this.cert ? this.cert : this.getKey.bind(this);
        return new Promise<boolean>((resolve, reject) => {
            jwt.verify(token, certOrGetKey, {
                audience: this.audiences,
                issuer: this.issuers,
            }, err => {
                if (err) {
                    reject(err);
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

    private getKey(header: JwtHeader, callback: SigningKeyCallback) {
        this.client.getSigningKey(header.kid, ((err, key) => {
            if (err) {
                return callback(err, null);
            }

            const signingKey =
                (key as jwksClient.CertSigningKey).publicKey ||
                (key as jwksClient.RsaSigningKey).rsaPublicKey;
            callback(null, signingKey);
        }));
    }
}
