export interface SeverityStyle {
  text: string;
  bg: string;
  border: string;
}

export function getSeverityStyle(severity?: string): SeverityStyle {
  const norm = (severity || 'informational').toLowerCase().trim();
  switch (norm) {
    case 'critical':
      return {
        text: 'text-red-400',
        bg: 'bg-red-500/10',
        border: 'border-red-500/20'
      };
    case 'high':
      return {
        text: 'text-amber-400',
        bg: 'bg-amber-500/10',
        border: 'border-amber-500/20'
      };
    case 'medium':
      return {
        text: 'text-yellow-400',
        bg: 'bg-yellow-500/10',
        border: 'border-yellow-500/20'
      };
    case 'low':
      return {
        text: 'text-cyan-400',
        bg: 'bg-cyan-500/10',
        border: 'border-cyan-500/20'
      };
    case 'informational':
    case 'info':
    default:
      return {
        text: 'text-slate-400',
        bg: 'bg-slate-500/10',
        border: 'border-slate-500/20'
      };
  }
}
