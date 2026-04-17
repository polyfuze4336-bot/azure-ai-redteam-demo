import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import AttackConsole from './pages/AttackConsole'
import CampaignHistory from './pages/CampaignHistory'
import ComparisonView from './pages/ComparisonView'

function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<AttackConsole />} />
        <Route path="history" element={<CampaignHistory />} />
        <Route path="compare" element={<ComparisonView />} />
      </Route>
    </Routes>
  )
}

export default App
