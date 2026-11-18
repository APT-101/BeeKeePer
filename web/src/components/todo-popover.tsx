"use client";

import * as React from "react";
import { ListTodo } from "lucide-react";

import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { cn } from "@/lib/utils";
import { api } from "@/lib/api";
import type { ExplorationTodoRow } from "@/lib/types";

// TodoPopover shows the task's planner todo snapshot (db-backed, so it reflects
// system auto-satisfy + fact bindings — §8.10/§8.11) or, for chat conversations
// without a task, the latest TodoWrite state parsed from the activity detail.
// Callers supply either taskId (db snapshot) or seq + fetchDetail (activity).
type TodoRow = {
  content: string;
  status: string;
  fact_id?: number | null;
  depends?: number[];
};

export function TodoPopover({
  taskId,
  seq,
  fetchDetail,
}: {
  taskId?: string;
  seq?: number | null;
  fetchDetail?: (seq: number) => Promise<string>;
}) {
  const [open, setOpen] = React.useState(false);
  const [todos, setTodos] = React.useState<TodoRow[] | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [err, setErr] = React.useState("");

  const load = React.useCallback(async () => {
    setLoading(true);
    setErr("");
    try {
      if (taskId) {
        const d = await api.explorationDecisions(taskId);
        setTodos(
          (Array.isArray(d.todos) ? d.todos : []).map((t: ExplorationTodoRow) => ({
            content: t.title,
            status: t.status,
            fact_id: t.fact_id ?? null,
            depends: t.depends ?? [],
          })),
        );
        return;
      }
      if (seq == null || !fetchDetail) {
        setTodos([]);
        return;
      }
      const detail = await fetchDetail(seq);
      const start = detail.indexOf("{");
      const parsed = JSON.parse(start >= 0 ? detail.slice(start) : detail);
      const arr = Array.isArray(parsed?.todos) ? parsed.todos : [];
      setTodos(
        arr.map((t: Record<string, unknown>) => ({
          content: String(t.content ?? ""),
          status: String(t.status ?? "pending"),
          fact_id: typeof t.satisfied_by_fact_id === "number" ? (t.satisfied_by_fact_id as number) : null,
          depends: Array.isArray(t.depends_on) ? (t.depends_on as number[]) : [],
        })),
      );
    } catch {
      setErr("解析 Todo 失败");
      setTodos(null);
    } finally {
      setLoading(false);
    }
  }, [taskId, seq, fetchDetail]);

  // refetch on each open — todos change as the run progresses.
  React.useEffect(() => {
    if (open) load();
  }, [open, load]);

  const disabled = !taskId && seq == null;
  const MARK: Record<string, string> = { pending: "☐", in_progress: "▶", completed: "✔" };
  return (
    <Popover open={open} onOpenChange={disabled ? undefined : setOpen}>
      <PopoverTrigger asChild>
        <button
          type="button"
          disabled={disabled}
          title={disabled ? "暂无 Todo" : taskId ? "查看任务规划待办（DB 快照）" : "查看最近 Todo"}
          className="text-muted-foreground/70 hover:text-primary flex items-center gap-0.5 text-xs disabled:pointer-events-none disabled:opacity-40"
        >
          <ListTodo className="size-3" />
          Todo
        </button>
      </PopoverTrigger>
      <PopoverContent align="end" className="max-h-80 w-80 overflow-auto p-2">
        <p className="text-muted-foreground px-1 pb-1 text-[11px] font-medium">
          {taskId ? "任务规划待办（DB 快照）" : "最近 Todo"}
          {loading ? " · 加载中…" : ""}
        </p>
        {err && <p className="text-destructive px-1 text-xs">{err}</p>}
        {todos && todos.length === 0 && !loading && (
          <p className="text-muted-foreground px-1 text-xs">（空）</p>
        )}
        <ul className="space-y-0.5">
          {(todos ?? []).map((t, i) => (
            <li
              key={`${i}:${t.content}`}
              className={cn(
                "flex items-start gap-1.5 px-1 text-xs",
                t.status === "completed" && "text-muted-foreground line-through",
              )}
            >
              <span className="shrink-0">{MARK[t.status] ?? "☐"}</span>
              <span className="min-w-0 flex-1 break-words">{t.content}</span>
              {t.fact_id != null && t.fact_id > 0 && (
                <span
                  title="由 fact 节点满足（satisfied_by_fact_id）"
                  className="shrink-0 rounded bg-primary/10 px-1 text-[10px] text-primary"
                >
                  fact #{t.fact_id}
                </span>
              )}
              {t.depends && t.depends.length > 0 && (
                <span title="依赖的前置步骤" className="shrink-0 text-[10px] text-muted-foreground">
                  依赖 {t.depends.map((d) => `#${d}`).join(",")}
                </span>
              )}
            </li>
          ))}
        </ul>
      </PopoverContent>
    </Popover>
  );
}