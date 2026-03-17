import { Routes, Route, Navigate } from "react-router-dom";
import AppLayout from "@/components/layout/AppLayout";
import Login from "@/pages/Login";
import Dashboard from "@/pages/Dashboard";
import Rules from "@/pages/Rules";
import RuleDetail from "@/pages/RuleDetail";
import IntakeQueue from "@/pages/IntakeQueue";
import LogSources from "@/pages/LogSources";
import Sync from "@/pages/Sync";
import ElkPage from "@/pages/ElkPage";
import Settings from "@/pages/Settings";

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route element={<AppLayout />}>
        <Route path="/" element={<Dashboard />} />
        <Route path="/rules" element={<Rules />} />
        <Route path="/rules/:id" element={<RuleDetail />} />
        <Route path="/intake" element={<IntakeQueue />} />
        <Route path="/log-sources" element={<LogSources />} />
        <Route path="/sync" element={<Sync />} />
        <Route path="/elk" element={<ElkPage />} />
        <Route path="/settings" element={<Settings />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
