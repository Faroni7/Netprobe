import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

interface TrafficChartProps {
  data: Array<{ timestamp: string; packets: number }>;
}

export default function TrafficChart({ data }: TrafficChartProps) {
  const chartData = data.map((item) => ({
    ...item,
    time: new Date(item.timestamp).toLocaleTimeString(),
  }));

  return (
    <ResponsiveContainer width="100%" height={300}>
      <LineChart data={chartData}>
        <CartesianGrid strokeDasharray="3 3" stroke="#333" />
        <XAxis 
          dataKey="time" 
          stroke="#666"
          tick={{ fontSize: 12 }}
        />
        <YAxis stroke="#666" tick={{ fontSize: 12 }} />
        <Tooltip
          contentStyle={{
            backgroundColor: '#1e1e1e',
            border: '1px solid #333',
            color: '#fff',
          }}
        />
        <Line
          type="monotone"
          dataKey="packets"
          stroke="#00bcd4"
          strokeWidth={2}
          dot={false}
        />
      </LineChart>
    </ResponsiveContainer>
  );
}
