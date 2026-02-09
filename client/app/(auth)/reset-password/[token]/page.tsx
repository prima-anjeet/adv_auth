
"use client";
import { resetPassword } from "@/app/services/auth.services";
import Link from "next/link";
import { useState, use } from "react";
import { z } from "zod";
import { resetPasswordSchema } from "@/app/lib/zod";
import { FormErrors } from "@/app/components/form-errors";
import { useRouter } from "next/navigation";
import { showToast } from "nextjs-toast-notify";
import RequireGuest from "@/app/components/require-guest";

type FormData = z.infer<typeof resetPasswordSchema>;

export default function ResetPasswordPage({ params }: { params: Promise<{ token: string }> }) {
  const { token } = use(params);
  const [formData, setFormData] = useState<FormData>({ password: "", confirmPassword: "" });
  const [isLoading, setIsLoading] = useState(false);
  const [errors, setErrors] = useState<z.ZodError | null>(null);
  const router = useRouter();

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const result = resetPasswordSchema.safeParse(formData);
    if (!result.success) {
      setErrors(result.error);
      return;
    }
    setErrors(null);
    setIsLoading(true);
    try {
      const response = await resetPassword({ password: result.data.password, token });
      showToast.success(response.message);
      router.push("/login");
    } catch (error: any) {
      showToast.error(error.response?.data?.message || "Reset failed");
    } finally {
      setIsLoading(false);
    }
  };

  const formattedErrors = errors?.format();

  return (
    <RequireGuest>
      <div className="flex items-center justify-center min-h-screen bg-gray-900 text-white">
        <div className="w-full max-w-md p-8 space-y-6 bg-gray-800 rounded-lg shadow-lg">
          <div className="text-center">
            <h1 className="text-3xl font-bold">Reset Password</h1>
            <p className="text-gray-400">Enter your new password</p>
          </div>
          <form className="space-y-6" onSubmit={handleSubmit} noValidate>
            <div>
              <label htmlFor="password" className="text-sm font-medium block mb-2">
                New Password
              </label>
              <input
                id="password"
                type="password"
                value={formData.password}
                required
                onChange={(e) =>
                  setFormData({ ...formData, password: e.target.value })
                }
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              {formattedErrors?.password?._errors && (
                <FormErrors errors={formattedErrors.password._errors} />
              )}
            </div>

             <div>
              <label htmlFor="confirmPassword" className="text-sm font-medium block mb-2">
                Confirm Password
              </label>
              <input
                id="confirmPassword"
                type="password"
                value={formData.confirmPassword}
                required
                onChange={(e) =>
                  setFormData({ ...formData, confirmPassword: e.target.value })
                }
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              {formattedErrors?.confirmPassword?._errors && (
                <FormErrors errors={formattedErrors.confirmPassword._errors} />
              )}
            </div>

            <button
              type="submit"
              className="w-full py-2 px-4 bg-blue-600 hover:bg-blue-700 rounded-md font-semibold transition cursor-pointer"
              disabled={isLoading}
            >
              {isLoading ? "Resetting..." : "Reset Password"}
            </button>
             <div className="text-center text-sm text-gray-400">
                <Link href="/login" className="text-blue-400 hover:text-blue-300">
                    Back to Login
                </Link>
            </div>
          </form>
        </div>
      </div>
    </RequireGuest>
  );
}
