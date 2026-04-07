import abc
import asyncio

class KurokamiModule(abc.ABC):
    """
    Abstract base class for all KUROKAMI standalone tools/modules.
    Every module must implement the async execute() method and define metadata.
    """
    
    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Name of the module (e.g. 'Nmap Recon')"""
        pass
        
    @property
    @abc.abstractmethod
    def description(self) -> str:
        """Description of what the module does"""
        pass
        
    @property
    @abc.abstractmethod
    def tool_schema(self) -> dict:
        """JSON function call schema for the AI agentic loop to invoke this module"""
        pass

    @abc.abstractmethod
    async def execute(self, target: str, **kwargs) -> dict:
        """
        Async execution of the tool.
        Must return a structured dictionary containing 'status', 'output', and 'findings' (if any).
        """
        pass
