import { ReflectMetadata } from '@nestjs/common';

export const PublicRoute = () => ReflectMetadata('public-route', true);
