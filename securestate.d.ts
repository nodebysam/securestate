declare module 'securestate' {
    import { Request, Response, NextFunction } from 'express';

    interface CookieUtils {
        getCookie(req: Request, name: string): string | null;
        setCookie(req: Response, name: string, value: string, options?: { [key: string]: any }): void;
    }

    interface SecureStateOptions {
        tokenLength?: number;
        tokenExpiration?: number;
        checkOrigin: boolean;
        cookieOptions: { [key: string]: any };
        regenerateToken?: boolean;
    }

    function csrfMiddleware(option?: SecureStateOptions): (req: Request, res: Response, next: NextFunction) => void;

    export = csrfMiddleware;

    export const CookieUtils: CookieUtils;

    class DataStore {
        private store: { [key: string]: any };
        static getInstance(): DataStore;
        set(key: string, value: any): void;
        get(key: string): any | null;
        exists(key: string): boolean;
        size(): number;
        getAll(): { [key: string]: any };
        clear(): void;
    }

    export const dataStore: DataStore;

    function mockRes() {
        setHeader: jest.Mock;
    }

    export { mockRes };

    export function generateToken(length: number, req: Request): string;
    export function validateToken(receivedToken: string, storedToken: string, req: Request | null): boolean;
}