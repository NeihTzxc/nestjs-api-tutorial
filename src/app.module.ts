import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { AuthService } from './auth/auth.service';
import { BookmarkModule } from './bookmark/bookmark.module';
import { PrismaModule } from './prisma/prisma.module';
import { UserModule } from './user/user.module';
import { ConfigModule } from '@nestjs/config'
@Module({
  imports: [AuthModule, PrismaModule, UserModule, BookmarkModule, ConfigModule.forRoot({isGlobal: true})],
  providers: [AuthService],
})
export class AppModule {}
