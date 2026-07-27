"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import apiClient from "@/services/api";

export default function LoginForm() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [isLogin, setIsLogin] = useState(true);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const endpoint = isLogin ? "/auth/login" : "/auth/register";
      const res = await apiClient.post(endpoint, { email, password });

      if (res.data.token) {
        localStorage.setItem("token", res.data.token);
        router.push("/");
      } else if (!isLogin) {
        setIsLogin(true);
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || "Something went wrong");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-sm rounded-2xl bg-white p-8 shadow-lg dark:bg-slate-800 dark:text-slate-100">
      <h1 className="mb-6 text-center text-2xl font-bold">
        AI Kubernetes Agent
      </h1>

      {error && <p className="mb-4 text-sm text-red-600">{error}</p>}

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
            Email
          </label>
          <input
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="mt-1 w-full rounded border bg-white px-3 py-2 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-100"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
            Password
          </label>
          <input
            type="password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mt-1 w-full rounded border bg-white px-3 py-2 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-100"
          />
        </div>
        <button
          type="submit"
          disabled={loading}
          className="w-full rounded-lg bg-blue-600 px-4 py-2 font-medium text-white hover:bg-blue-700 disabled:opacity-50"
        >
          {loading ? "Please wait..." : isLogin ? "Log in" : "Register"}
        </button>
      </form>

      <p className="mt-4 text-center text-sm text-slate-600 dark:text-slate-300">
        {isLogin ? "Need an account? " : "Already have an account? "}
        <button
          onClick={() => setIsLogin(!isLogin)}
          className="text-blue-600 hover:underline dark:text-blue-400"
        >
          {isLogin ? "Register" : "Log in"}
        </button>
      </p>
    </div>
  );
}
