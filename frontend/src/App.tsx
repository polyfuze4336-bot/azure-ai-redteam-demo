import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Overview from './pages/Overview'
import AttackConsole from './pages/AttackConsole'
import CampaignHistory from './pages/CampaignHistory'
import ComparisonView from './pages/ComparisonView'
import Agents from './pages/Agents'

function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Overview />} />
        <Route path="console" element={<AttackConsole />} />
        <Route path="history" element={<CampaignHistory />} />
        <Route path="compare" element={<ComparisonView />} />
        <Route path="agents" element={<Agents />} />
      </Route>
    </Routes>
  )
}

export default App
