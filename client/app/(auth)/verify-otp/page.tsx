"use client";
import { otpVerify } from "@/app/services/auth.services";
import { showToast } from "nextjs-toast-notify";
import { useState } from "react";
import { z } from "zod";
import { FormErrors } from "@/app/components/form-errors";
import { otpSchema } from "@/app/lib/zod";
import { useRouter } from "next/navigation";
import RequireGuest from "@/app/components/require-guest";
import { useAuth } from "@/app/context/auth-context";
export default function VerifyOtpPage() {
  
  const [otp, setOtp] = useState<string>("");
  const [btnLoading, setBtnLoading] = useState(false);
  const [errors, setErrors] = useState<z.ZodError | null>(null);
  const router = useRouter();
  const { refreshProfile } = useAuth();
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
      router.push("/dashboard");
    } catch (error: any) {
      showToast.error(error.response?.data?.message || "OTP verification failed");
    } finally {
      setBtnLoading(false);
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
          </form>
        </div>
      </div>
    </RequireGuest>
  );
}
