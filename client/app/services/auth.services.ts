import axiosInstance from "../lib/axios";
import {
  AuthResponse,
  LoginRequest,
  OtpVerifyRequest,
  ProfileResponse,
  RegisterRequest,
  VerifyEmailResponse,
} from "../types";

export const login = async(data:LoginRequest):Promise<AuthResponse> => {
    const response = await axiosInstance.post<AuthResponse>("/api/v1/login", data);
    return response.data;
}
export const otpVerify = async(data:OtpVerifyRequest):Promise<AuthResponse> => {
    const response = await axiosInstance.post<AuthResponse>("/api/v1/verify-otp", data);
    return response.data;
}

export const register = async(data:RegisterRequest):Promise<AuthResponse> => {
    const response = await axiosInstance.post<AuthResponse>("/api/v1/register", data);
    return response.data;
}

export const verifyEmail = async (token: string): Promise<VerifyEmailResponse> => {
  const safeToken = encodeURIComponent(token);
  const response = await axiosInstance.get<VerifyEmailResponse>(`/api/v1/verify/${safeToken}`);
  return response.data;
};

export const getMyProfile = async (): Promise<ProfileResponse> => {
  const response = await axiosInstance.get<ProfileResponse>("/api/v1/my-profile");
  return response.data;
};

export const refreshToken = async (): Promise<{ message: string; accessToken?: string }> => {
  const response = await axiosInstance.get("/api/v1/refresh-token");
  return response.data;
};

export const logout = async (): Promise<{ message: string }> => {
  const response = await axiosInstance.post("/api/v1/logout");
  return response.data;
};
