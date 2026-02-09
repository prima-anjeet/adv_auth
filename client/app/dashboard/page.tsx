import RequireAuth from "@/app/components/require-auth";
export default function DashboardPage() {
  return (
    <RequireAuth>
      <div>Dashboard</div>
    </RequireAuth>
  );
}

