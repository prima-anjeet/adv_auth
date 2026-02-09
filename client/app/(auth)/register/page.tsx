
"use client";
import Link from "next/link";
import { useState } from "react";
import RequireGuest from "@/app/components/require-guest";
import {registerSchema } from "@/app/lib/zod";
import { z } from "zod";
import { FormErrors } from "@/app/components/form-errors";
import { showToast } from "nextjs-toast-notify";
import { register } from "@/app/services/auth.services";
import { useRouter } from "next/navigation";

type FormData = z.infer<typeof registerSchema>;
export default function RegisterPage() {
  const router = useRouter();
  const [formData, setFormData] = useState<FormData>({ username: "", email: "", password: "" });
  const [isLoading, setIsLoading] = useState(false);
  const [errors, setErrors] = useState<z.ZodError | null>(null);
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
       const result = registerSchema.safeParse(formData);
         if (!result.success) {
           setErrors(result.error);
           return;
         }
         setErrors(null);
         setIsLoading(true);
          try {
             const response =await register(result.data);
              showToast.success(response.message);
              setFormData({ username: "", email: "", password: "" });
              router.push("/verify-email");
          }catch(error: any){
            showToast.error(error.response?.data?.message || "Registration failed");
          }finally{
            setIsLoading(false);
          }
    console.log({ ...formData });
  };

const formattedErrors = errors?.format();

  return (
    <RequireGuest>
      <div className="flex items-center justify-center min-h-screen bg-gray-900 text-white">
        <div className="w-full max-w-md p-8 space-y-6 bg-gray-800 rounded-lg shadow-lg">
          <div className="text-center">
            <h1 className="text-3xl font-bold">Create an Account</h1>
            <p className="text-gray-400">Join us and start your journey</p>
          </div>
          <form className="space-y-6" onSubmit={handleSubmit} noValidate>
            <div>
              <label
                htmlFor="username"
                className="text-sm font-medium block mb-2"
              >
                Username
              </label>
              <input
                id="username"
                type="text"
                value={formData.username}
                onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                placeholder="Your username"
                required
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
                  {formattedErrors?.username?._errors && (
                <FormErrors errors={formattedErrors.username._errors} />
              )}
            </div>
            <div>
              <label htmlFor="email" className="text-sm font-medium block mb-2">
                Email
              </label>
              <input
                id="email"
                type="email"
                value={formData.email}
                onChange={(e) => setFormData({ ...formData, email: e.target.value })}
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
                onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                required
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
                 {formattedErrors?.password?._errors && (
                <FormErrors errors={formattedErrors.password._errors} />
              )}
            </div>
            <button
              type="submit"
              className="w-full py-2 px-4 bg-blue-600 hover:bg-blue-700 rounded-md font-semibold transition"
              disabled={isLoading}
            >
             {isLoading ? "Creating account..." : "Create an account"}
            </button>
          </form>
          <div className="mt-4 text-center text-sm text-gray-400">
            Already have an account?{" "}
            <Link href="/login" className="underline hover:text-blue-400">
              Sign in
            </Link>
          </div>
        </div>
      </div>
    </RequireGuest>
  );
}
