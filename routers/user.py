from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

router = APIRouter(prefix='/user', tags=['user'])

@router.get('/')
async def getUsers(request: Request):
    try:
        return JSONResponse({ 'a': 1, 'b': { 'c': 2 } })
    except Exception as e:
        print("Error: ", e)
        raise HTTPException(status_code=500, detail=f"str({e})")