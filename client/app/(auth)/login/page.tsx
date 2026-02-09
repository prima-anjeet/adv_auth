
"use client";
import { login } from "@/app/services/auth.services";
import Link from "next/link";
import { useState } from "react";
import { z } from "zod";
import { loginSchema } from "@/app/lib/zod";
import { FormErrors } from "@/app/components/form-errors";
import { useRouter } from "next/navigation";
import { showToast } from "nextjs-toast-notify";
import RequireGuest from "@/app/components/require-guest";


type FormData = z.infer<typeof loginSchema>;

export default function LoginPage() {
  const [formData, setFormData] = useState<FormData>({ email: "", password: "" });
  const [isLoading, setIsLoading] = useState(false);
  const [errors, setErrors] = useState<z.ZodError | null>(null);
  const router = useRouter();
  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const result = loginSchema.safeParse(formData);
    if (!result.success) {
      setErrors(result.error);
      return;
    }
    setErrors(null);
    setIsLoading(true);
    try {
      const response = await login(result.data);
      console.log(response);
      showToast.success(response.message);
      localStorage.setItem("email", formData.email);
      router.push("/verify-otp"); 
    } catch (error: any) {
      showToast.error(error.response?.data?.message || "Login failed");
    }finally{
      setIsLoading(false);
    }
  };

  const formattedErrors = errors?.format();

  return (
    <RequireGuest>
      <div className="flex items-center justify-center min-h-screen bg-gray-900 text-white">
        <div className="w-full max-w-md p-8 space-y-6 bg-gray-800 rounded-lg shadow-lg">
          <div className="text-center">
            <h1 className="text-3xl font-bold">Welcome Back</h1>
            <p className="text-gray-400">Sign in to continue</p>
          </div>
          <form className="space-y-6" onSubmit={handleSubmit} noValidate>
            <div>
              <label htmlFor="email" className="text-sm font-medium block mb-2">
                Email
              </label>
              <input
                id="email"
                type="email"
                value={formData.email}
                onChange={(e) =>
                  setFormData({ ...formData, email: e.target.value })
                }
                placeholder="m@example.com"
                required
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              {formattedErrors?.email?._errors && (
                <FormErrors errors={formattedErrors.email._errors} />
              )}
            </div>
            <div>
              <label
                htmlFor="password"
                className="text-sm font-medium block mb-2"
              >
                Password
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
            <button
              type="submit"
              className="w-full py-2 px-4 bg-blue-600 hover:bg-blue-700 rounded-md font-semibold transition cursor-pointer"
              disabled={isLoading}
            >
              {isLoading ? "Logging in..." : "Login"}
            </button>
          </form>
          <div className="mt-4 text-center text-sm text-gray-400">
            Don't have an account?{" "}
            <Link
              href="/register"
              className="underline hover:text-blue-400 cursor-pointer"
            >
              Sign up
            </Link>
          </div>
        </div>
      </div>
    </RequireGuest>
  );
}

