
export interface LoginRequest{
    email: string;
    password: string;
}
export interface OtpVerifyRequest{
    email: string;
    otp: string;
    error?: string;
}
export interface RegisterRequest{
    username: string;
    email: string;
    password: string;
}

export interface ForgotPasswordRequest {
    email: string;
}

export interface ResetPasswordRequest {
    password: string;
    token: string;
}

export interface User{
    id?:string;
    _id?: string;
    username: string;
    email: string;
    role: string;
}
export interface VerifyEmailResponse {
  success?: boolean;
  message: string;
  user?: User;
}
export interface AuthResponse {
  token: string;
  user: User;
  message: string;
  error: string;
}

export interface ProfileResponse {
  success: boolean;
  user?: User;
  message?: string;
}
