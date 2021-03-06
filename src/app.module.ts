import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { AuthService } from './auth/auth.service';
import { BookmarkModule } from './bookmark/bookmark.module';
import { PrismaModule } from './prisma/prisma.module';
import { ConfigModule } from '@nestjs/config'
import { UserController } from './user/user.controller';
@Module({
  imports: [AuthModule, PrismaModule, BookmarkModule, ConfigModule.forRoot({isGlobal: true})],
  controllers: [UserController],
})
export class AppModule {}
