"use client";
import { otpVerify, resendOtp } from "@/app/services/auth.services";
import { showToast } from "nextjs-toast-notify";
import { useState, useEffect } from "react";
import { z } from "zod";
import { FormErrors } from "@/app/components/form-errors";
import { otpSchema } from "@/app/lib/zod";
import { useRouter } from "next/navigation";
import RequireGuest from "@/app/components/require-guest";
import { useAuth } from "@/app/context/auth-context";

export default function VerifyOtpPage() {
  
  const [otp, setOtp] = useState<string>("");
  const [btnLoading, setBtnLoading] = useState(false);
  const [resendLoading, setResendLoading] = useState(false);
  const [timer, setTimer] = useState(0);
  const [errors, setErrors] = useState<z.ZodError | null>(null);
  const router = useRouter();
  const { refreshProfile } = useAuth();
  
  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (timer > 0) {
      interval = setInterval(() => {
        setTimer((prev) => prev - 1);
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [timer]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrors(null);
    const result = otpSchema.safeParse({ otp });
    if (!result.success) {
      setErrors(result.error);
      return;
    }

    setBtnLoading(true);
    const email = localStorage.getItem("email") || "";
    try {
      const response = await otpVerify({ email, otp });
      showToast.success(response.message);
      localStorage.removeItem("email");
      await refreshProfile();
      router.replace("/");
    } catch (error: any) {
      showToast.error(error.response?.data?.message || "OTP verification failed");
    } finally {
      setBtnLoading(false);
    }
  };

  const handleResend = async () => {
    const email = localStorage.getItem("email");
    if (!email) {
      showToast.error("Email not found. Please login again.");
      router.push("/login");
      return;
    }

    setResendLoading(true);
    try {
      const response = await resendOtp(email);
      showToast.success(response.message);
      setTimer(60); // Start 60s cooldown
    } catch (error: any) {
      showToast.error(error.response?.data?.message || "Failed to resend OTP");
    } finally {
      setResendLoading(false);
    }
  };

  return (
    <RequireGuest>
      <div className="flex items-center justify-center min-h-screen bg-gray-900 text-white">
        <div className="w-full max-w-md p-8 space-y-6 bg-gray-800 rounded-lg shadow-lg">
          <div className="text-center">
            <h1 className="text-3xl font-bold">Verify OTP</h1>
            <p className="text-gray-400">Enter the OTP sent to your email</p>
          </div>
          <form className="space-y-6" onSubmit={handleSubmit} noValidate>
            <div>
              <label htmlFor="otp" className="text-sm font-medium block mb-2">
                OTP
              </label>

              <input
                id="otp"
                type="text"
                value={otp}
                onChange={(e) => setOtp(e.target.value)}
                placeholder="123456"
                required
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <FormErrors errors={errors?.format()?.otp?._errors} />
            </div>
            <button
              type="submit"
              className="w-full py-2 px-4 bg-blue-600 hover:bg-blue-700 rounded-md font-semibold transition cursor-pointer"
              disabled={btnLoading}
            >
              {btnLoading ? "Verifying..." : "Verify OTP"}
            </button>
            <div className="text-center mt-4">
              <p className="text-gray-400 text-sm">
                Didn't receive code?{" "}
                <button
                  type="button"
                  onClick={handleResend}
                  disabled={timer > 0 || resendLoading}
                  className={`text-blue-400 hover:text-blue-300 font-medium ${
                    timer > 0 || resendLoading ? "opacity-50 cursor-not-allowed" : "cursor-pointer"
                  }`}
                >
                  {resendLoading
                    ? "Sending..."
                    : timer > 0
                    ? `Resend in ${timer}s`
                    : "Resend Code"}
                </button>
              </p>
            </div>
          </form>
        </div>
      </div>
    </RequireGuest>
  );
}
