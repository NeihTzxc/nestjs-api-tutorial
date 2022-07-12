import { AuthDto } from './dto/auth.dto';
import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import * as argon from 'argon2'
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
@Injectable({})
export class AuthService{
    constructor(private prisma: PrismaService, private config: ConfigService, private jwt: JwtService){}
    async signup(dto: AuthDto) {
        //generate the password hash
        const hash = await argon.hash(dto.password)
        //save the new user in the db
        try {
            const user = this.prisma.user.create({
                data: {
                    email: dto.email,
                    hash
                }
            }) 
            //return the saved user
            return user
        } catch(err) {
            if (err instanceof PrismaClientKnownRequestError) {
                if (err.code === 'P2002') {
                    throw new ForbiddenException('Credentials taken')
                }
            }
            throw err
        }
        
    }
    async signin(dto: AuthDto) {
        //find the user by email
        const user = await this.prisma.user.findUnique({
            where: {
                email: dto.email
            }
        })
        // if user does not exists thrown exception
        if (!user) throw new ForbiddenException('Credentials incorrect')
        //compare pasword
        const pwMatches = await argon.verify(user.hash, dto.password)
        //if password incorrect throw exception
        if (!pwMatches) throw new ForbiddenException('Credentials incorrect')
        return this.signToken(user.id, user.email)
    }
    async signToken(userId: number, email: string): Promise<{access_token: string}> {
        const payload = {
            sub: userId,
            email
        }
        const secret = this.config.get('JWT_SECRET')
        const access_token = await this.jwt.signAsync(
            payload,
            {
                expiresIn: '15m',
                secret: secret
            }
        )
        return {
            access_token
        }
    }
}
// const service = new AuthService()