from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from auth.jwt_handler import get_current_voter
from blockchain.block import MainBlockchain
from db.crud_voters import get_verified_vote_results
router = APIRouter()
blockchain = MainBlockchain()

class VoteRequest(BaseModel):
    candidate: str

from db.crud_candidates import get_all_candidates, candidate_exists

@router.post("/vote")
def cast_vote(request: VoteRequest, current_user: dict = Depends(get_current_voter)):
    tc = current_user["tc"]
    region = current_user["region"]
    
    if not candidate_exists(request.candidate):
        raise HTTPException(status_code=400, detail="Geçersiz aday ismi")

    try:
        blockchain.vote(region=region, voter_id=tc, candidate=request.candidate)
        return {"message": "Oy başarıyla kaydedildi", "region": region, "candidate": request.candidate}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/results")
def get_results():
    return blockchain.get_all_results()

@router.get("/chains")
def get_chains():
    return blockchain.get_all_chains()
@router.get("/structure")
def get_merkle_structure():
    return blockchain.get_merkle_structure()

@router.get("/candidates")
def list_candidates():
    return {"candidates": get_all_candidates()}

@router.get("/results/verified")
def get_verified_results():
    return get_verified_vote_results()
