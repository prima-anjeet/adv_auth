import RequireAuth from "@/app/components/require-auth";
export default function DashboardPage() {
  return (
    <RequireAuth>
      <div className="flex justify-start items-center p-4 text-black font-bold">Dashboard</div>
    </RequireAuth>
  );
}

